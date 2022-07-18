package nmap

import (
	"errors"
)

var (
	// ErrNmapNotInstalled means that upon trying to manually locate nmap in the user's path,
	// it was not found. Either use the WithBinaryPath method to set it manually, or make sure that
	// the nmap binary is present in the user's $PATH.
	ErrNmapNotInstalled = errors.New("nmap binary was not found")

	// ErrScanTimeout means that the provided context was done before the scanner finished its scan.
	ErrScanTimeout = errors.New("nmap scan timed out")

	// ErrParseOutput means that nmap's output was not parsed successfully.
	ErrParseOutput = errors.New("unable to parse nmap output, see warnings for details")

	// ErrResolveName means that Nmap could not resolve a name.
	ErrResolveName = errors.New("nmap could not resolve a name")
)
