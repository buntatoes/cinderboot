<div align="center">
  <img src="assets/icon.svg" alt="Cinderboot" width="110" />

  # Cinderboot

  Modern, **zero-dependency** bootable USB creator for **Linux and Windows** — built from scratch in pure Go standard library (**GPL-3.0**).

  <p>
    <a href="https://github.com/buntatoes/cinderboot/releases/latest"><img src="https://img.shields.io/badge/release-v0.0.3-orange" alt="Release" /></a>
    <img src="https://img.shields.io/badge/dependencies-0%20(Go%20stdlib)-brightgreen" alt="Zero Dependencies" />
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue" alt="Platform" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="GPL-3.0" /></a>
  </p>
</div>

## Why Cinderboot?

- **vs. Rufus**: Rufus is outdated, legacy Win32, and **Windows-only**. Cinderboot is a clean, modern, cross-platform replacement that runs identically on **Linux and Windows**, includes its own pure-Go GPT/FAT32/UDF/ISO9660/WIM-split engine, and boots Windows 10/11 USBs natively under strict UEFI Secure Boot with zero third-party bootloader blobs.
- **vs. Balena Etcher**: Etcher is a slow, bloated Electron wrapper with telemetry baggage and no Windows ISO or customization support. Cinderboot is a single lightweight static binary (~7 MB), streams at full USB speed with SHA-256 verification, and handles both Linux ISOs and Windows 10/11 ISOs (`autounattend.xml` customization included).

## Highlights

- **Zero External Dependencies**: Pure Go standard library (`CGO_ENABLED=0`), no Electron, no runtime frameworks, and no `ntfs-3g`, `wimlib`, `7z`, or `mkfs.*` required.
- **Windows 10/11 & Linux ISOs**: Direct raw streaming for hybrid Linux ISOs / `.img` / `.gz` / `.bz2` / `.zip`, plus pure-Go UDF 1.02 reading, lossless >4 GiB `install.wim` → `.swm` splitting for Secure Boot FAT32, and optional `autounattend.xml` tweaks (TPM/Secure Boot/RAM bypass, local account `BypassNRO`, BitLocker off, skip OOBE privacy).
- **Safe & Resilient**: Strictly filters for removable USB drives, blocks internal/OS disks, recovers automatically from transient USB I/O stalls, escalates privileges only during flashing (`pkexec` / UAC), and supports SHA-256 read-back verification.
- **Desktop UI + CLI in One Binary**: Launch `cinderboot` for the desktop UI, or use `list`, `inspect`, `flash`, and `verify` from any terminal.

## Quick Start

### Linux (`x86_64`)
```bash
tar -xzf cinderboot-linux-x86_64.tar.gz && cd cinderboot-linux-x86_64
./cinderboot --install
cinderboot
```

### Windows (`x86_64`)
Download `cinderboot-v0.0.3-win64.exe` from [Releases](../../releases) and run it directly (portable, no installer needed).

### CLI
```bash
cinderboot list
cinderboot inspect /path/to/image.iso
cinderboot flash --image /path/to/linux.iso --device /dev/sdX --verify
cinderboot flash --image /path/to/Win11.iso --device /dev/sdX --win-bypass-req --win-bypass-msa
```

## Build from Source

Requires only **Go 1.24+**:
```bash
make test
make package
```

## License

Source code is licensed under **GNU GPL-3.0** ([LICENSE](LICENSE)) — by **Buntato**.
The **Cinderboot** name, logo, icons, and branding remain All Rights Reserved.
