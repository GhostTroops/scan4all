# z-base-32 - human-oriented base-32 encoding

[![Build Status](https://img.shields.io/travis/corvus-ch/zbase32.svg)](https://travis-ci.org/corvus-ch/zbase32)
[![Test Coverage](https://img.shields.io/codecov/c/github/corvus-ch/zbase32.svg)](https://codecov.io/gh/corvus-ch/zbase32)
[![Documentation](https://godoc.org/gopgk.in/corvus-ch/zbase32.v1?status.svg)](https://godoc.org/gopkg.in/corvus-ch/zbase32.v1)


Golang pacakge which implements base32 encoding of binary data according to
http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt.

Note: this is *NOT* RFC4648 or RFC3548. If you need to be compatible to one of
those RFCs, use `encoding/base32`.

This package:

* follows the example of `encoding/base32`;
* supports encoding and decoding of byte arrays;
* supports encoding and decoding using `io.Writer` and `io.Reader` interfaces.
* provides a shell command which behaves similar to the BSD base64 command.

Based on the work from `github.com/tv42/zbase32` by [Tommi
Virtanen](https://github.com/tv42).

## Command line utilities

Included is a simple command-line utility for encoding/decoding data.

Example:

```console
$ echo "Hello world" | zbase32
jb1sa5dxrb5s6huccofy
$ echo -n jb1sa5dxrb5s6huccofy | zbase32 --decode 
Hello world
$ printf '\x01binary!!!1\x00' | zbase32
yftg15ubqjh1nejbgryy
$ echo -n yftg15ubqjh1nejbgryy | zbase32 --decode | hexdump -C
00000000  01 62 69 6e 61 72 79 21  21 21 31 00              |.binary!!!1.|
0000000c
```

## Contributing and license

This library is licences under [MIT](LICENSE). For information about how to
contribute, see [CONTRIBUTING](CONTRIBUTING.md)
