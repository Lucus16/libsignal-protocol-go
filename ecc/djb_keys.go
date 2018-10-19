package ecc

import "github.com/Lucus16/curve25519-go"

import "bytes"
import "fmt"

const djbType = 5

type djbPublicKey struct {
	curve.PublicKey
}

type djbKeypair struct {
	curve.PrivateKey
	djbPublicKey
}

func (key djbPublicKey) EncodePublicKey() []byte {
	return append([]byte{djbType}, key.PublicKey...)
}

func (key djbKeypair) EncodePrivateKey() []byte {
	return append([]byte{}, key.PrivateKey...)
}

func (key djbPublicKey) LessThan(other PublicKey) bool {
	switch typedOther := other.(type) {
	case djbPublicKey:
		return bytes.Compare(key.PublicKey, typedOther.PublicKey) < 0
	case djbKeypair:
		return bytes.Compare(key.PublicKey, typedOther.djbPublicKey.PublicKey) < 0
	default:
		panic(fmt.Errorf("Attempt to compare %T and %T", key, other))
	}
}

func (keypair djbKeypair) CalculateAgreement(publicKey PublicKey) ([]byte, error) {
	switch typedPublicKey := publicKey.(type) {
	case djbPublicKey:
		return keypair.PrivateKey.CalculateAgreement(typedPublicKey.PublicKey)
	case djbKeypair:
		return keypair.PrivateKey.CalculateAgreement(typedPublicKey.djbPublicKey.PublicKey)
	default:
		return nil, fmt.Errorf("Attempt to calculate agreement between %T and %T",
			keypair.PrivateKey, publicKey)
	}
}
