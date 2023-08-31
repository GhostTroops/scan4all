package osutils

import "runtime"

type ArchType uint8

const (
	I386 ArchType = iota
	Amd64
	Amd64p32
	Arm
	Armbe
	Arm64
	Arm64be
	Loong64
	Mips
	Mipsle
	Mips64
	Mips64le
	Mips64p32
	Mips64p32le
	Ppc
	Ppc64
	Ppc64le
	Riscv
	Riscv64
	S390
	S390x
	Sparc
	Sparc64
	Wasm
	UknownArch
)

var Arch ArchType

func init() {
	switch {
	case Is386():
		Arch = I386
	case IsAmd64():
		Arch = Amd64
	case IsARM():
		Arch = Arm
	case IsARM64():
		Arch = Arm64
	case IsWasm():
		Arch = Wasm
	default:
		Arch = UknownArch
	}
}

func Is386() bool {
	return runtime.GOARCH == "386"
}

func IsAmd64() bool {
	return runtime.GOARCH == "amd64"
}

func IsARM() bool {
	return runtime.GOARCH == "arm"
}

func IsARM64() bool {
	return runtime.GOARCH == "arm64"
}

func IsWasm() bool {
	return runtime.GOARCH == "wasm"
}
