# Security Policy

## Supported Versions

Only the latest published release of **Cinderboot** receives security updates and bug fixes.

| Version | Supported |
| ------- | --------- |
| Latest (`v0.0.x`) | Yes |
| Older releases | No |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report vulnerabilities privately using GitHub Security Advisories:

- **Private Vulnerability Report**: https://github.com/buntatoes/cinderboot/security/advisories/new

Please include:
- Affected version and operating system (Linux or Windows).
- Clear steps to reproduce the issue (e.g., privilege elevation, loopback UI, disk selection, or malformed ISO/UDF/WIM parsing).
- Potential impact and any suggested remediation.

Reports will be acknowledged as promptly as possible and addressed in a new release.

## Security Design & Guarantees

- **Zero External Dependencies**: Built strictly on the Go standard library (`CGO_ENABLED=0`) with zero third-party Go modules, zero bundled third-party bootloaders, and zero external CLI dependencies (`mkfs.*`, `ntfs-3g`, `wimlib`, `7z`, etc.).
- **Privilege Separation**: The desktop UI runs unprivileged and invokes `cinderboot worker` with elevated privileges (`pkexec` on Linux, UAC `runas` on Windows) only for the duration of an active flash operation.
- **Loopback UI Isolation**: The local desktop UI binds strictly to `127.0.0.1` on an ephemeral port, enforces `Host` header validation and a strict `Content-Security-Policy`, and authenticates every API call with a per-session cryptographic random token.
- **Hardware Write Guards**: Cinderboot strictly filters for removable USB devices and rejects internal drives or OS-critical mounts (`/` , `/boot`, `/boot/efi`, `/home`, `C:\`, etc.) before opening any block device for writing.
- **Zero Telemetry**: Cinderboot makes zero outbound network requests and collects no analytics, hardware identifiers, or usage data.
