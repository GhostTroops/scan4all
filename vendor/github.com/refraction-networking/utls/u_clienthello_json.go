package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/gaukas/godicttls"
)

var ErrUnknownExtension = errors.New("extension name is unknown to the dictionary")

type ClientHelloSpecJSONUnmarshaler struct {
	CipherSuites       *CipherSuitesJSONUnmarshaler       `json:"cipher_suites"`
	CompressionMethods *CompressionMethodsJSONUnmarshaler `json:"compression_methods"`
	Extensions         *TLSExtensionsJSONUnmarshaler      `json:"extensions"`
	TLSVersMin         uint16                             `json:"min_vers,omitempty"` // optional
	TLSVersMax         uint16                             `json:"max_vers,omitempty"` // optional
}

func (chsju *ClientHelloSpecJSONUnmarshaler) ClientHelloSpec() ClientHelloSpec {
	return ClientHelloSpec{
		CipherSuites:       chsju.CipherSuites.CipherSuites(),
		CompressionMethods: chsju.CompressionMethods.CompressionMethods(),
		Extensions:         chsju.Extensions.Extensions(),
		TLSVersMin:         chsju.TLSVersMin,
		TLSVersMax:         chsju.TLSVersMax,
	}
}

type CipherSuitesJSONUnmarshaler struct {
	cipherSuites []uint16
}

func (c *CipherSuitesJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var cipherSuiteNames []string
	if err := json.Unmarshal(jsonStr, &cipherSuiteNames); err != nil {
		return err
	}

	for _, name := range cipherSuiteNames {
		if name == "GREASE" {
			c.cipherSuites = append(c.cipherSuites, GREASE_PLACEHOLDER)
			continue
		}

		if id, ok := godicttls.DictCipherSuiteNameIndexed[name]; ok {
			c.cipherSuites = append(c.cipherSuites, id)
		} else {
			return fmt.Errorf("unknown cipher suite name: %s", name)
		}
	}

	return nil
}

func (c *CipherSuitesJSONUnmarshaler) CipherSuites() []uint16 {
	return c.cipherSuites
}

type CompressionMethodsJSONUnmarshaler struct {
	compressionMethods []uint8
}

func (c *CompressionMethodsJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var compressionMethodNames []string
	if err := json.Unmarshal(jsonStr, &compressionMethodNames); err != nil {
		return err
	}

	for _, name := range compressionMethodNames {
		if id, ok := godicttls.DictCompMethNameIndexed[name]; ok {
			c.compressionMethods = append(c.compressionMethods, id)
		} else {
			return fmt.Errorf("unknown compression method name: %s", name)
		}
	}

	return nil
}

func (c *CompressionMethodsJSONUnmarshaler) CompressionMethods() []uint8 {
	return c.compressionMethods
}

type TLSExtensionsJSONUnmarshaler struct {
	AllowUnknownExt bool // if set, unknown extensions will be added as GenericExtension, without recovering ext payload
	UseRealPSK      bool // if set, PSK extension will be real PSK extension, otherwise it will be fake PSK extension
	extensions      []TLSExtensionJSON
}

func (e *TLSExtensionsJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var accepters []tlsExtensionJSONAccepter
	if err := json.Unmarshal(jsonStr, &accepters); err != nil {
		return err
	}

	var exts []TLSExtensionJSON = make([]TLSExtensionJSON, 0, len(accepters))
	for _, accepter := range accepters {
		if accepter.extNameOnly.Name == "GREASE" {
			exts = append(exts, &UtlsGREASEExtension{})
			continue
		}

		if extID, ok := godicttls.DictExtTypeNameIndexed[accepter.extNameOnly.Name]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownExtension, accepter.extNameOnly.Name)
		} else {
			// get extension type from ID
			var ext TLSExtension = ExtensionFromID(extID)
			if ext == nil {
				if e.AllowUnknownExt {
					// fallback to generic extension, without recovering ext payload
					ext = genericExtension(extID, accepter.extNameOnly.Name)
				} else {
					return fmt.Errorf("extension %s (%d) is not JSON compatible", accepter.extNameOnly.Name, extID)
				}
			}

			switch extID {
			case extensionPreSharedKey:
				// PSK extension, need to see if we do real or fake PSK
				if e.UseRealPSK {
					ext = &UtlsPreSharedKeyExtension{}
				} else {
					ext = &FakePreSharedKeyExtension{}
				}
			}

			if extJsonCompatible, ok := ext.(TLSExtensionJSON); ok {
				exts = append(exts, extJsonCompatible)
			} else {
				return fmt.Errorf("extension %s (%d) is not JSON compatible", accepter.extNameOnly.Name, extID)
			}
		}
	}

	// unmashal extensions
	for idx, ext := range exts {
		// json.Unmarshal will call the UnmarshalJSON method of the extension
		if err := json.Unmarshal(accepters[idx].origJsonInput, ext); err != nil {
			return err
		}
	}

	e.extensions = exts
	return nil
}

func (e *TLSExtensionsJSONUnmarshaler) Extensions() []TLSExtension {
	var exts []TLSExtension = make([]TLSExtension, 0, len(e.extensions))
	for _, ext := range e.extensions {
		exts = append(exts, ext)
	}
	return exts
}

func genericExtension(id uint16, name string) TLSExtension {
	var warningMsg string = "WARNING: extension "
	warningMsg += fmt.Sprintf("%d ", id)
	if len(name) > 0 {
		warningMsg += fmt.Sprintf("(%s) ", name)
	}
	warningMsg += "is falling back to generic extension"
	warningMsg += "\n"

	fmt.Fprint(os.Stderr, warningMsg)

	// fallback to generic extension
	return &GenericExtension{Id: id}
}

type tlsExtensionJSONAccepter struct {
	extNameOnly struct {
		Name string `json:"name"`
	}
	origJsonInput []byte
}

func (t *tlsExtensionJSONAccepter) UnmarshalJSON(jsonStr []byte) error {
	t.origJsonInput = make([]byte, len(jsonStr))
	copy(t.origJsonInput, jsonStr)
	return json.Unmarshal(jsonStr, &t.extNameOnly)
}
