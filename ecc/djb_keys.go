package ecc

import "github.com/Lucus16/curve25519-go"
import "fmt"

type djbPublicKey struct {
	curve.PublicKey
}

type djbPrivateKey struct {
	curve.PrivateKey
}

func (key djbPublicKey) Encode() []byte {
	return append([]byte{djbType}, key.PublicKey...)
}

func (key djbPrivateKey) Encode() []byte {
	return key.PrivateKey
}

func (privateKey djbPrivateKey) CalculateAgreement(publicKey PublicKey) (agreement []byte, err error) {
	djbKey, ok := publicKey.(djbPublicKey)
	if !ok {
		return nil, fmt.Errorf("Key type mismatch")
	}
	return privateKey.PrivateKey.CalculateAgreement(djbKey.PublicKey)
}
