# Contributing to Cinderboot

Thank you for your interest in contributing to **Cinderboot**! Please read this contributor notice carefully before opening an issue or pull request.

## Contributor Notice & Licensing

- **Code License (GNU GPL-3.0)**: By submitting a pull request, patch, or other contribution to this repository, you agree that your contribution is original work that you have the right to submit and that it will be licensed under the **GNU General Public License v3.0 ([LICENSE](LICENSE))**.
- **SPDX Header**: Every new Go source file must include `// SPDX-License-Identifier: GPL-3.0-only` on its first line.
- **Branding & Trademarks**: The **Cinderboot** name, flame-USB logo, icons, and visual identity remain **All Rights Reserved** by **Buntato**. Forks or derivative distributions must use a distinct name and icon.

## Core Project Rules

1. **Zero External Dependencies**: `go.mod` must remain pure Go standard library only (`CGO_ENABLED=0`). Do not add third-party Go packages, web/Electron runtimes, prebuilt binary blobs, or external CLI tool requirements.
2. **Linux & Windows Parity**: All changes must remain drive- and mount-agnostic and compile cleanly for both `linux/amd64` and `windows/amd64`.
3. **Hardware Safety First**: Never weaken removable-USB filtering, OS-disk detection, or destructive-write confirmation guards in `internal/device` or `internal/flash`.
4. **Sanitized Submissions**: Never include personal file paths, local usernames, hostnames, drive serial numbers, credentials, or sensitive environment details in commits, tests, logs, or issue reports.

## Local Development & Verification

Requires **Go 1.24+**:

```bash
# Static analysis for both Linux and Windows
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...

# Run unit tests with race detection (uses temporary virtual disk files; no USB hardware needed)
go test -v -race ./...

# Build Linux tarball and Windows portable executable into dist/
make package
```

## Pull Request Checklist

- [ ] `go vet ./...` and `GOOS=windows GOARCH=amd64 go vet ./...` pass with zero warnings.
- [ ] `go test -v -race ./...` passes and new behavior is covered by unit tests.
- [ ] Zero external dependencies added to `go.mod`.
- [ ] New `.go` files include `// SPDX-License-Identifier: GPL-3.0-only`.
- [ ] Diff contains no personal paths, local usernames, or sensitive data.

## Security Issues

Do **not** open a public issue or PR for security vulnerabilities. Report them privately via [SECURITY.md](SECURITY.md).
