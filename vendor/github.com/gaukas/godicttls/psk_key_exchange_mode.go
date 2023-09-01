package godicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-pskkeyexchangemode.csv
// last updated: March 2023

const (
	PSKKeyExchangeMode_psk_ke     uint8 = 0
	PSKKeyExchangeMode_psk_dhe_ke uint8 = 1
)

var DictPSKKeyExchangeModeValueIndexed = map[uint8]string{
	0: "psk_ke",
	1: "psk_dhe_ke",
}

var DictPSKKeyExchangeModeNameIndexed = map[string]uint8{
	"psk_ke":     0,
	"psk_dhe_ke": 1,
}
