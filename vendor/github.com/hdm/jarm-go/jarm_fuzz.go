// +build gofuzz

package jarm

// Fuzzing code for use with github.com/dvyukov/go-fuzz
//
// To use, in the main project directory do:
//
//   go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
//   go-fuzz-build
//   go-fuzz

func Fuzz(data []byte) int {
	details := JarmProbeOptions{Hostname: "console.example.com", Port: 443, Version: 772, Ciphers: "ALL", CipherOrder: "MIDDLE_OUT", Grease: "GREASE", ALPN: "ALPN", V13Mode: "1.3_Support", ExtensionOrder: "REVERSE"}
	_, err := ParseServerHello(data, details)
	if err == nil {
		return 1
	}
	return 0
}
