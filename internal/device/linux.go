// SPDX-License-Identifier: GPL-3.0-only
//go:build linux

package device

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	linuxBLKRRPART = 0x125f
	linuxBLKFLSBUF = 0x1261
)

// ListRemovable returns removable USB block devices detected via Linux sysfs.
// Internal OS, NVMe, SATA, loop, dm, and root-mounted disks are excluded.
func ListRemovable(opts ListOptions) ([]Drive, error) {
	mounts, err := readProcMounts("/proc/mounts")
	if err != nil {
		mounts = nil
	}

	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, fmt.Errorf("read /sys/block: %w", err)
	}

	var drives []Drive
	for _, entry := range entries {
		name := entry.Name()
		if shouldSkipBlockName(name) {
			continue
		}

		sysDir := filepath.Join("/sys/block", name)
		realPath, err := filepath.EvalSymlinks(sysDir)
		if err != nil {
			continue
		}

		isUSB := strings.Contains(realPath, "/usb")
		if !isUSB {
			continue
		}

		removable := readSysTrim(filepath.Join(sysDir, "removable")) == "1"
		if !removable && !opts.IncludeFixedUSB {
			continue
		}

		sectors, err := strconv.ParseUint(readSysTrim(filepath.Join(sysDir, "size")), 10, 64)
		if err != nil || sectors == 0 {
			continue
		}
		sectorSize := uint32(512)
		if lbs, err := strconv.ParseUint(readSysTrim(filepath.Join(sysDir, "queue/logical_block_size")), 10, 32); err == nil && lbs > 0 {
			sectorSize = uint32(lbs)
		}

		devPath := "/dev/" + name
		mps := mountsForDevice(mounts, devPath)
		isSystem := false
		for _, mp := range mps {
			if IsProtectedMount(mp) {
				isSystem = true
				break
			}
		}
		if isSystem {
			continue
		}

		drives = append(drives, Drive{
			ID:           name,
			DevicePath:   devPath,
			Vendor:       readSysTrim(filepath.Join(sysDir, "device/vendor")),
			Model:        readSysTrim(filepath.Join(sysDir, "device/model")),
			Serial:       readSysTrim(filepath.Join(sysDir, "device/serial")),
			SizeBytes:    sectors * 512, // Linux sysfs size is always in 512-byte sectors
			SectorSize:   sectorSize,
			BusType:      "USB",
			Removable:    removable,
			IsUSB:        true,
			IsSystemDisk: false,
			MountPoints:  mps,
		})
	}

	sort.Slice(drives, func(i, j int) bool {
		return drives[i].DevicePath < drives[j].DevicePath
	})
	return drives, nil
}

// FindByPath locates a single removable USB drive matching devPath.
func FindByPath(devPath string, opts ListOptions) (Drive, error) {
	drives, err := ListRemovable(opts)
	if err != nil {
		return Drive{}, err
	}
	clean := filepath.Clean(devPath)
	for _, d := range drives {
		if d.DevicePath == clean || d.ID == clean {
			return d, nil
		}
	}
	return Drive{}, fmt.Errorf("%w: %s", ErrDriveNotFound, devPath)
}

// PrepareForWrite unmounts all mounted partitions belonging to devPath.
func PrepareForWrite(d Drive) error {
	if err := ValidateTarget(d, true); err != nil {
		return err
	}
	mounts, err := readProcMounts("/proc/mounts")
	if err != nil {
		return fmt.Errorf("read /proc/mounts: %w", err)
	}
	type mpEntry struct {
		dev   string
		point string
	}
	var toUnmount []mpEntry
	for _, m := range mounts {
		if isDeviceOrPartition(m.device, d.DevicePath) {
			if IsProtectedMount(m.mountPoint) {
				return fmt.Errorf("%w: %s mounted at %s", ErrSystemDisk, m.device, m.mountPoint)
			}
			toUnmount = append(toUnmount, mpEntry{dev: m.device, point: m.mountPoint})
		}
	}
	sort.Slice(toUnmount, func(i, j int) bool {
		return len(toUnmount[i].point) > len(toUnmount[j].point)
	})
	for _, item := range toUnmount {
		var uErr error
		for attempt := 0; attempt < 4; attempt++ {
			uErr = syscall.Unmount(item.point, 0)
			if uErr == nil {
				break
			}
			if uErr == syscall.EBUSY && attempt < 3 {
				time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
				continue
			}
			break
		}
		if uErr != nil {
			return fmt.Errorf("unmount %s (%s): %w", item.dev, item.point, uErr)
		}
	}
	return nil
}

// OpenRawWrite opens the Linux block device exclusively for raw writing.
func OpenRawWrite(d Drive) (*os.File, error) {
	if err := ValidateTarget(d, true); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(d.DevicePath, syscall.O_RDWR|syscall.O_EXCL|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s for exclusive write: %w", d.DevicePath, err)
	}
	return os.NewFile(uintptr(fd), d.DevicePath), nil
}

// OpenRawRead opens the Linux block device read-only for verification.
func OpenRawRead(d Drive) (*os.File, error) {
	fd, err := syscall.Open(d.DevicePath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s for read: %w", d.DevicePath, err)
	}
	return os.NewFile(uintptr(fd), d.DevicePath), nil
}

// FlushReadCache drops Linux block device page caches (BLKFLSBUF) so subsequent
// verification reads directly from physical USB flash storage rather than RAM.
func FlushReadCache(f *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), linuxBLKFLSBUF, 0)
	if errno != 0 {
		return fmt.Errorf("BLKFLSBUF on %s: %w", f.Name(), errno)
	}
	return nil
}

// RereadPartitionTable tells the Linux kernel to rescan partitions on an open block device.
func RereadPartitionTable(f *os.File) error {
	_ = f.Sync()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), linuxBLKRRPART, 0)
	if errno != 0 {
		return fmt.Errorf("BLKRRPART on %s: %w", f.Name(), errno)
	}
	return nil
}

// RereadPartitionTablePath opens devPath non-exclusively after writing completes
// and asks the Linux kernel to rescan the partition table (retrying briefly on EBUSY).
func RereadPartitionTablePath(devPath string) error {
	fd, err := syscall.Open(devPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s for partition reread: %w", devPath, err)
	}
	f := os.NewFile(uintptr(fd), devPath)
	defer f.Close()

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if err := RereadPartitionTable(f); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	return lastErr
}

func shouldSkipBlockName(name string) bool {
	prefixes := []string{"loop", "ram", "dm-", "zram", "sr", "md", "nbd", "fd"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readSysTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

type procMount struct {
	device     string
	mountPoint string
}

func readProcMounts(path string) ([]procMount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []procMount
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		out = append(out, procMount{
			device:     unescapeOctal(fields[0]),
			mountPoint: unescapeOctal(fields[1]),
		})
	}
	return out, sc.Err()
}

func unescapeOctal(s string) string {
	s = strings.ReplaceAll(s, `\040`, " ")
	s = strings.ReplaceAll(s, `\011`, "\t")
	s = strings.ReplaceAll(s, `\012`, "\n")
	s = strings.ReplaceAll(s, `\134`, `\`)
	return s
}

func isDeviceOrPartition(mountedDev, baseDev string) bool {
	if mountedDev == baseDev {
		return true
	}
	if !strings.HasPrefix(mountedDev, baseDev) {
		return false
	}
	rest := mountedDev[len(baseDev):]
	if len(rest) == 0 {
		return true
	}
	if rest[0] == 'p' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' {
		return true
	}
	return rest[0] >= '0' && rest[0] <= '9'
}

func mountsForDevice(mounts []procMount, baseDev string) []string {
	var out []string
	for _, m := range mounts {
		if isDeviceOrPartition(m.device, baseDev) {
			out = append(out, m.mountPoint)
		}
	}
	return out
}
