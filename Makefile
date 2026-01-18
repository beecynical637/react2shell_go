.PHONY: build clean

build: build-linux-amd64 build-macos-amd64 build-macos-arm64 build-windows-amd64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o bin/react2shell_linux_amd64 ./cmd/react2shell

build-macos-amd64:
	GOOS=darwin GOARCH=amd64 go build -o bin/react2shell_macos_intel ./cmd/react2shell

build-macos-arm64:
	GOOS=darwin GOARCH=arm64 go build -o bin/react2shell_macos_apple_silicon ./cmd/react2shell

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o bin/react2shell_windows_amd64.exe ./cmd/react2shell

clean:
	rm -f bin/*
