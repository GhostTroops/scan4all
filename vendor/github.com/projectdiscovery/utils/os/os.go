package osutils

import "runtime"

type OsType uint8

const (
	Darwin OsType = iota
	windows
	Linux
	Android
	IOS
	FreeBSD
	OpenBSD
	JS
	Solaris
	UnknownOS
)

var OS OsType

func init() {
	switch {
	case IsOSX():
		OS = Darwin
	case IsLinux():
		OS = Linux
	case IsWindows():
		OS = windows
	case IsAndroid():
		OS = Android
	case IsIOS():
		OS = IOS
	case IsJS():
		OS = JS
	case IsFreeBSD():
		OS = FreeBSD
	case IsOpenBSD():
		OS = OpenBSD
	case IsSolaris():
		OS = Solaris
	default:
		OS = UnknownOS
	}
}

func IsOSX() bool {
	return runtime.GOOS == "darwin"
}

func IsLinux() bool {
	return runtime.GOOS == "linux"
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func IsAndroid() bool {
	return runtime.GOOS == "android"
}

func IsIOS() bool {
	return runtime.GOOS == "ios"
}

func IsFreeBSD() bool {
	return runtime.GOOS == "freebsd"
}

func IsOpenBSD() bool {
	return runtime.GOOS == "openbsd"
}

func IsJS() bool {
	return runtime.GOOS == "js"
}

func IsSolaris() bool {
	return runtime.GOOS == "solaris"
}
