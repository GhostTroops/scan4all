# ![uTLS](logo_small.png) uTLS
[![Build Status](https://github.com/refraction-networking/utls/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/refraction-networking/utls/actions/workflows/go.yml) 
[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/refraction-networking/utls#UConn)
---
uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting resistance, low-level access to handshake, fake session tickets and some other features. Handshake is still performed by "crypto/tls", this library merely changes ClientHello part of it and provides low-level access.  

**Minimum Go Version**: Go 1.21 

If you have any questions, bug reports or contributions, you are welcome to publish those on GitHub. If you want to do so in private, ~~you can contact one of developers personally via sergey.frolov@colorado.edu~~.

You can contact one of developers personally via gaukas.wang@colorado.edu.

Documentation below may not keep up with all the changes and new features at all times,
so you are encouraged to use [godoc](https://godoc.org/github.com/refraction-networking/utls#UConn).

*Note: Information provided below in this README.md could be obsolete. We welcome 
any contributions to refresh the documentations in addition to code contributions.*

# Features
## Low-level access to handshake
* Read/write access to all bits of client hello message.  
* Read access to fields of ClientHandshakeState, which, among other things, includes ServerHello and MasterSecret.
* Read keystream. Can be used, for example, to "write" something in ciphertext.

## ClientHello fingerprinting resistance
Golang's ClientHello has a very unique fingerprint, which especially sticks out on mobile clients,
where Golang is not too popular yet.
Some members of anti-censorship community are concerned that their tools could be trivially blocked based on
ClientHello with relatively small collateral damage. There are multiple solutions to this issue.

**It is highly recommended to use multiple fingeprints, including randomized ones to avoid relying on a single fingerprint.**
[utls.Roller](#roller) does this automatically.

### Randomized Fingerprint
Randomized Fingerprints are supposedly good at defeating blacklists, since
those fingerprints have random ciphersuites and extensions in random order.
Note that all used ciphersuites and extensions are fully supported by uTLS,
which provides a solid moving target without any compatibility or parrot-is-dead attack risks.  

But note that there's a small chance that generated fingerprint won't work,
so you may want to keep generating until a working one is found,
and then keep reusing the working fingerprint to avoid suspicious behavior of constantly changing fingerprints.
[utls.Roller](#roller) reuses working fingerprint automatically.

#### Generating randomized fingerprints

To generate a randomized fingerprint, simply do:
```Golang
uTlsConn := tls.UClient(tcpConn, &config, tls.HelloRandomized)
```
you can use `helloRandomizedALPN` or `helloRandomizedNoALPN` to ensure presence or absence of
ALPN(Application-Layer Protocol Negotiation) extension.
It is recommended, but certainly not required to include ALPN (or use helloRandomized which may or may not include ALPN).
If you do use ALPN, you will want to correctly handle potential application layer protocols (likely h2 or http/1.1).

#### Reusing randomized fingerprint
```Golang
// oldConn is an old connection that worked before, so we want to reuse it
// newConn is a new connection we'd like to establish
newConn := tls.UClient(tcpConn, &config, oldConn.ClientHelloID)
```

### Parroting
This package can be used to parrot ClientHello of popular browsers.
There are some caveats to this parroting:
* We are forced to offer ciphersuites and tls extensions that are not supported by crypto/tls.
This is not a problem, if you fully control the server and turn unsupported things off on server side.
* Parroting could be imperfect, and there is no parroting beyond ClientHello.
#### Compatibility risks of available parrots

| Parrot        | Ciphers* | Signature* | Unsupported extensions | TLS Fingerprint ID              |
| ------------- | -------- | ---------- | ---------------------- | --------------------------------------------- |
| Chrome 62     | no       | no         | ChannelID              | [0a4a74aeebd1bb66](https://tlsfingerprint.io/id/0a4a74aeebd1bb66) |
| Chrome 70     | no       | no         | ChannelID, Encrypted Certs | [bc4c7e42f4961cd7](https://tlsfingerprint.io/id/bc4c7e42f4961cd7) |
| Chrome 72     | no       | no         | ChannelID, Encrypted Certs | [bbf04e5f1881f506](https://tlsfingerprint.io/id/bbf04e5f1881f506) |
| Chrome 83     | no       | no         | ChannelID, Encrypted Certs | [9c673fd64a32c8dc](https://tlsfingerprint.io/id/9c673fd64a32c8dc) |
| Firefox 56    | very low | no         | None                   | [c884bad7f40bee56](https://tlsfingerprint.io/id/c884bad7f40bee56) |
| Firefox 65    | very low | no         | MaxRecordSize                   | [6bfedc5d5c740d58](https://tlsfingerprint.io/id/6bfedc5d5c740d58) |
| iOS 11.1      | low** | no         | None                   | [71a81bafd58e1301](https://tlsfingerprint.io/id/71a81bafd58e1301) |
| iOS 12.1      | low** | no         | None                   | [ec55e5b4136c7949](https://tlsfingerprint.io/id/ec55e5b4136c7949) |

\* Denotes very rough guesstimate of likelihood that unsupported things will get echoed back by the server in the wild,
*visibly breaking the connection*.  
\*\* No risk, if `utls.EnableWeakCiphers()` is called prior to using it.  

#### Parrots FAQ
> Does it really look like, say, Google Chrome with all the [GREASE](https://tools.ietf.org/html/draft-davidben-tls-grease-01) and stuff?

It LGTM, but please open up Wireshark and check. If you see something — [say something](https://github.com/refraction-networking/utls/issues).

> Aren't there side channels? Everybody knows that the ~~bird is a word~~[parrot is dead](https://people.cs.umass.edu/~amir/papers/parrot.pdf)

There sure are. If you found one that approaches practicality at line speed — [please tell us](https://github.com/refraction-networking/utls/issues).

However, there is a difference between this sort of parroting and techniques like SkypeMorth.
Namely, TLS is highly standardized protocol, therefore simply not that many subtle things in TLS protocol
could be different and/or suddenly change in one of mimicked implementation(potentially undermining the mimicry).
It is possible that we have a distinguisher right now, but amount of those potential distinguishers is limited.

### Custom Handshake
It is possible to create custom handshake by
1) Use `HelloCustom` as an argument for `UClient()` to get empty config
2) Fill tls header fields: UConn.Hello.{Random, CipherSuites, CompressionMethods}, if needed, or stick to defaults.
3) Configure and add various [TLS Extensions](u_tls_extensions.go) to UConn.Extensions: they will be marshaled in order.
4) Set Session and SessionCache, as needed.

If you need to manually control all the bytes on the wire(certainly not recommended!),
you can set UConn.HandshakeStateBuilt = true, and marshal clientHello into UConn.HandshakeState.Hello.raw yourself.
In this case you will be responsible for modifying other parts of Config and ClientHelloMsg to reflect your setup
and not confuse "crypto/tls", which will be processing response from server.

### Fingerprinting Captured Client Hello
You can use a captured client hello to generate new ones that mimic/have the same properties as the original.
The generated client hellos _should_ look like they were generated from the same client software as the original fingerprinted bytes.
In order to do this:
1) Create a `ClientHelloSpec` from the raw bytes of the original client hello
2) Use `HelloCustom` as an argument for `UClient()` to get empty config
3) Use `ApplyPreset` with the generated `ClientHelloSpec` to set the appropriate connection properties
```
uConn := UClient(&net.TCPConn{}, nil, HelloCustom)
fingerprinter := &Fingerprinter{}
generatedSpec, err := fingerprinter.FingerprintClientHello(rawCapturedClientHelloBytes)
if err != nil {
  panic("fingerprinting failed: %v", err)
}
if err := uConn.ApplyPreset(generatedSpec); err != nil {
  panic("applying generated spec failed: %v", err)
}
```
The `rawCapturedClientHelloBytes` should be the full tls record, including the record type/version/length header.

## Roller

A simple wrapper, that allows to easily use multiple latest(auto-updated) fingerprints.

```Golang
// NewRoller creates Roller object with default range of HelloIDs to cycle
// through until a working/unblocked one is found.
func NewRoller() (*Roller, error)
```

```Golang
// Dial attempts to connect to given address using different HelloIDs.
// If a working HelloID is found, it is used again for subsequent Dials.
// If tcp connection fails or all HelloIDs are tried, returns with last error.
//
// Usage examples:
//
// Dial("tcp4", "google.com:443", "google.com")
// Dial("tcp", "10.23.144.22:443", "mywebserver.org")
func (c *Roller) Dial(network, addr, serverName string) (*UConn, error)
```

## Fake Session Tickets
Fake session tickets is a very nifty trick that allows power users to hide parts of handshake, which may have some very fingerprintable features of handshake, and saves 1 RTT.
Currently, there is a simple function to set session ticket to any desired state:

```Golang
// If you want you session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionState(session *ClientSessionState)
```

Note that session tickets (fake ones or otherwise) are not reused.  
To reuse tickets, create a shared cache and set it on current and further configs:

```Golang
// If you want you session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionCache(cache ClientSessionCache)
```

## Custom TLS extensions
If you want to add your own fake (placeholder, without added functionality) extension for mimicry purposes, you can embed `*tls.GenericExtension` into your own struct and override `Len()` and `Read()` methods. For example, [DelegatedCredentials](https://datatracker.ietf.org/doc/draft-ietf-tls-subcerts/) extension can be implemented as follows:

```Golang
const FakeDelegatedCredentials uint16 = 0x0022

type FakeDelegatedCredentialsExtension struct {
	*tls.GenericExtension
	SignatureAlgorithms []tls.SignatureScheme
}

func (e *FakeDelegatedCredentialsExtension) Len() int {
	return 6 + 2*len(e.SignatureAlgorithms)
}

func (e *FakeDelegatedCredentialsExtension) Read(b []byte) (n int, err error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	offset := 0
	appendUint16 := func(val uint16) {
		b[offset] = byte(val >> 8)
		b[offset+1] = byte(val & 0xff)
		offset += 2
	}

	// Extension type
	appendUint16(FakeDelegatedCredentials)

	algosLength := 2 * len(e.SignatureAlgorithms)

	// Extension data length
	appendUint16(uint16(algosLength) + 2)

	// Algorithms list length
	appendUint16(uint16(algosLength))

	// Algorithms list
	for _, a := range e.SignatureAlgorithms {
		appendUint16(uint16(a))
	}
	return e.Len(), io.EOF
}
```

Then it can be used just like normal extension:

```Golang
&tls.ClientHelloSpec{
	//...
	Extensions: []tls.TLSExtension{
		//...
		&FakeDelegatedCredentialsExtension{
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		},
		//...
	}
	//...
}
```

# Client Hello IDs
See full list of `clientHelloID` values [here](https://godoc.org/github.com/refraction-networking/utls#ClientHelloID).  
There are different behaviors you can get, depending  on your `clientHelloID`:

1. ```utls.HelloRandomized``` adds/reorders extensions, ciphersuites, etc. randomly.  
`HelloRandomized` adds ALPN in a percentage of cases, you may want to use `HelloRandomizedALPN` or
`HelloRandomizedNoALPN` to choose specific behavior explicitly, as ALPN might affect application layer.
2. ```utls.HelloGolang```
    HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
    overwrite your changes to Hello(Config, Session are fine).
    You might want to call BuildHandshakeState() before applying any changes.
    UConn.Extensions will be completely ignored.
3. ```utls.HelloCustom```
will prepare ClientHello with empty uconn.Extensions so you can fill it with TLSExtension's manually.
4. The rest will will parrot given browser. Such parrots include, for example:
	* `utls.HelloChrome_Auto`- parrots recommended(usually latest) Google Chrome version
	* `utls.HelloChrome_58` - parrots Google Chrome 58
	* `utls.HelloFirefox_Auto` - parrots recommended(usually latest) Firefox version
	* `utls.HelloFirefox_55` - parrots Firefox 55
	
# Usage
## Examples
Find basic examples [here](examples/examples.go).  
Here's a more [advanced example](https://github.com/sergeyfrolov/gotapdance/blob//9a777f35a04b0c4c5dacd30bca0e9224eb737b5e/tapdance/conn_raw.go#L275-L292) showing how to generate randomized ClientHello, modify generated ciphersuites a bit, and proceed with the handshake.
### Migrating from "crypto/tls"
Here's how default "crypto/tls" is typically used:
```Golang
    dialConn, err := net.Dial("tcp", "172.217.11.46:443")
    if err != nil {
        fmt.Printf("net.Dial() failed: %+v\n", err)
        return
    }

    config := tls.Config{ServerName: "www.google.com"}
    tlsConn := tls.Client(dialConn, &config)
    n, err = tlsConn.Write("Hello, World!")
    //...
```
To start using using uTLS:
1. Import this library (e.g. `import tls "github.com/refraction-networking/utls"`)
2. Pick the [Client Hello ID](#client-hello-ids)
3. Simply substitute `tlsConn := tls.Client(dialConn, &config)`
with `tlsConn := tls.UClient(dialConn, &config, tls.clientHelloID)`  

### Customizing handshake
Some customizations(such as setting session ticket/clientHello) have easy-to-use functions for them. The idea is to make common manipulations easy:
```Golang
    cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
        130, 131}
    tlsConn.SetClientRandom(cRandom)
    masterSecret := make([]byte, 48)
    copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

    // Create a session ticket that wasn't actually issued by the server.
    sessionState := utls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        masterSecret,
        nil, nil)
    tlsConn.SetSessionState(sessionState)
```

For other customizations there are following functions
```
// you can use this to build the state manually and change it
// for example use Randomized ClientHello, and add more extensions
func (uconn *UConn) BuildHandshakeState() error
```
```
// Then apply the changes and marshal final bytes, which will be sent
func (uconn *UConn) MarshalClientHello() error
```

## Contributors' guide
Please refer to [this document](./CONTRIBUTORS_GUIDE.md) if you're interested in internals

## Credits
The initial development of uTLS was completed during an internship at [Google Jigsaw](https://jigsaw.google.com/). This is not an official Google product.
