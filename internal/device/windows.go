// SPDX-License-Identifier: GPL-3.0-only
//go:build windows

package device

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDrvs = kernel32DLL.NewProc("GetLogicalDrives")
)

const (
	ioctlStorageQueryProperty       = 0x002D1400
	ioctlDiskGetDriveGeometryEx     = 0x000700A0
	ioctlDiskDeleteDriveLayout      = 0x0007C100
	ioctlDiskUpdateProperties       = 0x00070140
	ioctlVolumeGetVolumeDiskExtents = 0x00560000
	fsctlLockVolume                 = 0x00090018
	fsctlDismountVolume             = 0x00090020

	fileFlagWriteThrough = 0x80000000

	storageDeviceProperty = 0
	propertyStandardQuery = 0
	busTypeUSB            = 7
)

type storagePropertyQuery struct {
	PropertyID           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

type storageDeviceDescriptor struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIDOffset        uint32
	ProductIDOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
	RawDeviceProperties   [1]byte
}

type diskGeometryEx struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
	DiskSize          int64
	Data              [1]byte
}

// ListRemovable enumerates removable USB physical drives on Windows via Win32 IOCTLs (stdlib only).
func ListRemovable(opts ListOptions) ([]Drive, error) {
	diskLetters, sysDisk := mapDriveLettersToDisks()

	var drives []Drive
	for diskNum := uint32(0); diskNum < 64; diskNum++ {
		if diskNum == sysDisk {
			continue
		}
		devPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
		h, err := openDiskQueryHandle(devPath)
		if err != nil {
			continue
		}

		vendor, model, serial, busType, removable, qErr := queryStorageDescriptor(h)
		sizeBytes, sectorSize, gErr := queryDiskGeometry(h)
		_ = syscall.CloseHandle(h)

		if qErr != nil || gErr != nil || sizeBytes == 0 {
			continue
		}
		isUSB := (busType == busTypeUSB)
		if !isUSB {
			continue
		}
		if !removable && !opts.IncludeFixedUSB {
			continue
		}

		letters := diskLetters[diskNum]
		isSystem := false
		for _, l := range letters {
			if IsProtectedMount(l) {
				isSystem = true
				break
			}
		}
		if isSystem {
			continue
		}

		drives = append(drives, Drive{
			ID:           fmt.Sprintf("PhysicalDrive%d", diskNum),
			DevicePath:   devPath,
			Vendor:       vendor,
			Model:        model,
			Serial:       serial,
			SizeBytes:    sizeBytes,
			SectorSize:   sectorSize,
			BusType:      "USB",
			Removable:    removable,
			IsUSB:        true,
			IsSystemDisk: false,
			DriveLetters: letters,
			MountPoints:  letters,
			DiskNumber:   diskNum,
		})
	}

	sort.Slice(drives, func(i, j int) bool {
		return drives[i].DiskNumber < drives[j].DiskNumber
	})
	return drives, nil
}

// FindByPath locates a Windows USB physical drive by path, ID, or drive letter (e.g., "E:").
func FindByPath(devPath string, opts ListOptions) (Drive, error) {
	drives, err := ListRemovable(opts)
	if err != nil {
		return Drive{}, err
	}
	norm := strings.ToUpper(strings.TrimRight(strings.TrimSpace(devPath), `\`))
	for _, d := range drives {
		if strings.EqualFold(d.DevicePath, devPath) || strings.EqualFold(d.ID, devPath) {
			return d, nil
		}
		for _, l := range d.DriveLetters {
			if strings.EqualFold(strings.TrimRight(l, `\`), norm) {
				return d, nil
			}
		}
	}
	return Drive{}, fmt.Errorf("%w: %s", ErrDriveNotFound, devPath)
}

// PrepareForWrite locks and dismounts all volumes on the target disk and clears its partition table.
func PrepareForWrite(d Drive) error {
	if err := ValidateTarget(d, true); err != nil {
		return err
	}
	diskLetters, sysDisk := mapDriveLettersToDisks()
	if d.DiskNumber == sysDisk {
		return fmt.Errorf("%w: %s", ErrSystemDisk, d.DevicePath)
	}

	var lockedHandles []syscall.Handle
	defer func() {
		for _, h := range lockedHandles {
			_ = syscall.CloseHandle(h)
		}
	}()

	for _, letter := range diskLetters[d.DiskNumber] {
		volPath := fmt.Sprintf(`\\.\%s`, strings.TrimRight(letter, `\`))
		p, err := syscall.UTF16PtrFromString(volPath)
		if err != nil {
			continue
		}
		vh, err := syscall.CreateFile(
			p,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil,
			syscall.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil {
			continue
		}
		var bytesRet uint32
		locked := false
		for attempt := 0; attempt < 5; attempt++ {
			if err := syscall.DeviceIoControl(vh, fsctlLockVolume, nil, 0, nil, 0, &bytesRet, nil); err == nil {
				locked = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		_ = syscall.DeviceIoControl(vh, fsctlDismountVolume, nil, 0, nil, 0, &bytesRet, nil)
		if locked {
			lockedHandles = append(lockedHandles, vh)
		} else {
			_ = syscall.CloseHandle(vh)
		}
	}

	p, err := syscall.UTF16PtrFromString(d.DevicePath)
	if err != nil {
		return err
	}
	dh, err := syscall.CreateFile(
		p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("open %s to clear drive layout: %w", d.DevicePath, err)
	}
	defer syscall.CloseHandle(dh)

	var bytesRet uint32
	_ = syscall.DeviceIoControl(dh, ioctlDiskDeleteDriveLayout, nil, 0, nil, 0, &bytesRet, nil)
	_ = syscall.DeviceIoControl(dh, ioctlDiskUpdateProperties, nil, 0, nil, 0, &bytesRet, nil)
	return nil
}

// OpenRawWrite opens \\.\PhysicalDriveN for unbuffered raw writing.
func OpenRawWrite(d Drive) (*os.File, error) {
	if err := ValidateTarget(d, true); err != nil {
		return nil, err
	}
	p, err := syscall.UTF16PtrFromString(d.DevicePath)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagWriteThrough,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open %s for write (run elevated as Administrator): %w", d.DevicePath, err)
	}
	return os.NewFile(uintptr(h), d.DevicePath), nil
}

// OpenRawRead opens \\.\PhysicalDriveN read-only for verification.
func OpenRawRead(d Drive) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(d.DevicePath)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open %s for read: %w", d.DevicePath, err)
	}
	return os.NewFile(uintptr(h), d.DevicePath), nil
}

// RereadPartitionTable asks Windows to re-enumerate partitions on the target physical disk.
func RereadPartitionTable(f *os.File) error {
	_ = f.Sync()
	var bytesRet uint32
	return syscall.DeviceIoControl(syscall.Handle(f.Fd()), ioctlDiskUpdateProperties, nil, 0, nil, 0, &bytesRet, nil)
}

func openDiskQueryHandle(devPath string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(devPath)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(
		p,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
}

func queryStorageDescriptor(h syscall.Handle) (vendor, model, serial string, busType uint32, removable bool, err error) {
	q := storagePropertyQuery{
		PropertyID: storageDeviceProperty,
		QueryType:  propertyStandardQuery,
	}
	buf := make([]byte, 1024)
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		h,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&q)),
		uint32(unsafe.Sizeof(q)),
		&buf[0],
		uint32(len(buf)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return "", "", "", 0, false, err
	}
	if bytesRet < uint32(unsafe.Sizeof(storageDeviceDescriptor{})) {
		return "", "", "", 0, false, fmt.Errorf("short storage descriptor: %d", bytesRet)
	}
	desc := (*storageDeviceDescriptor)(unsafe.Pointer(&buf[0]))
	vendor = readCString(buf[:bytesRet], desc.VendorIDOffset)
	model = readCString(buf[:bytesRet], desc.ProductIDOffset)
	serial = readCString(buf[:bytesRet], desc.SerialNumberOffset)
	return vendor, model, serial, desc.BusType, desc.RemovableMedia != 0, nil
}

func queryDiskGeometry(h syscall.Handle) (uint64, uint32, error) {
	var geom diskGeometryEx
	var bytesRet uint32
	err := syscall.DeviceIoControl(
		h,
		ioctlDiskGetDriveGeometryEx,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geom)),
		uint32(unsafe.Sizeof(geom)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return 0, 512, err
	}
	sec := geom.BytesPerSector
	if sec == 0 {
		sec = 512
	}
	if geom.DiskSize < 0 {
		return 0, sec, nil
	}
	return uint64(geom.DiskSize), sec, nil
}

func readCString(buf []byte, off uint32) string {
	if off == 0 || int(off) >= len(buf) {
		return ""
	}
	end := int(off)
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(buf[off:end]))
}

func mapDriveLettersToDisks() (map[uint32][]string, uint32) {
	out := make(map[uint32][]string)
	sysDrive := strings.ToUpper(strings.TrimRight(os.Getenv("SystemDrive"), `\`))
	if sysDrive == "" {
		sysDrive = "C:"
	}
	sysDisk := uint32(0xFFFFFFFF)

	r1, _, _ := procGetLogicalDrvs.Call()
	mask := uint32(r1)
	if mask == 0 {
		return out, sysDisk
	}

	for i := 0; i < 26; i++ {
		if (mask & (1 << uint(i))) == 0 {
			continue
		}
		letter := fmt.Sprintf("%c:", 'A'+i)
		volPath := `\\.\` + letter
		p, err := syscall.UTF16PtrFromString(volPath)
		if err != nil {
			continue
		}
		h, err := syscall.CreateFile(
			p,
			0,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil,
			syscall.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil {
			continue
		}
		buf := make([]byte, 512)
		var bytesRet uint32
		err = syscall.DeviceIoControl(h, ioctlVolumeGetVolumeDiskExtents, nil, 0, &buf[0], uint32(len(buf)), &bytesRet, nil)
		_ = syscall.CloseHandle(h)
		if err != nil || bytesRet < 16 {
			continue
		}
		count := binary.LittleEndian.Uint32(buf[0:4])
		if count == 0 {
			continue
		}
		diskNum := binary.LittleEndian.Uint32(buf[8:12])
		out[diskNum] = append(out[diskNum], letter)
		if strings.EqualFold(letter, sysDrive) {
			sysDisk = diskNum
		}
	}
	return out, sysDisk
}
