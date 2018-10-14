package ecc

import "github.com/Lucus16/curve25519-go"
import "fmt"

const djbType = 5
const djbKeyLen = 0x20

type djbPublicKey struct {
	curve.PublicKey
}

type djbPrivateKey struct {
	curve.PrivateKey
}

type djbKeyPair struct {
	privateKey djbPrivateKey
	publicKey  djbPublicKey
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

func (keyPair djbKeyPair) PrivateKey() PrivateKey {
	return keyPair.privateKey
}

func (keyPair djbKeyPair) PublicKey() PublicKey {
	return keyPair.publicKey
}
