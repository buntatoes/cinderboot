VERSION := 0.0.4
LDFLAGS_COMMON := -s -w -X github.com/buntatoes/cinderboot/internal/version.Version=$(VERSION)

.PHONY: test vet build-linux build-windows package clean

test:
	CGO_ENABLED=0 go test -v ./...

vet:
	CGO_ENABLED=0 go vet ./...

build-linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS_COMMON)" -o dist/cinderboot ./cmd/cinderboot

build-windows:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS_COMMON)" -o dist/cinderboot-v$(VERSION)-win64.exe ./cmd/cinderboot

package: build-linux build-windows
	rm -rf dist/cinderboot-linux-x86_64
	mkdir -p dist/cinderboot-linux-x86_64/assets
	cp dist/cinderboot dist/cinderboot-linux-x86_64/cinderboot
	cp LICENSE README.md dist/cinderboot-linux-x86_64/
	cp packaging/linux/cinderboot.desktop dist/cinderboot-linux-x86_64/
	cp packaging/linux/com.buntatoes.cinderboot.policy dist/cinderboot-linux-x86_64/
	cp assets/icon.png assets/icon.svg dist/cinderboot-linux-x86_64/assets/
	tar -C dist -czf dist/cinderboot-linux-x86_64.tar.gz cinderboot-linux-x86_64
	rm -rf dist/cinderboot-linux-x86_64

clean:
	rm -rf dist
