package tls13

import fips140 "hash"

func NewEarlySecretFromSecret[H fips140.Hash](hash func() H, secret []byte) *EarlySecret {
	return &EarlySecret{
		secret: secret,
		hash:   func() fips140.Hash { return hash() },
	}
}

func (s *EarlySecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}

func NewMasterSecretFromSecret[H fips140.Hash](hash func() H, secret []byte) *MasterSecret {
	return &MasterSecret{
		secret: secret,
		hash:   func() fips140.Hash { return hash() },
	}
}

func (s *MasterSecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}
