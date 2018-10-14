package ecc

import "github.com/Lucus16/curve25519-go"
import "fmt"

func GenerateKeyPair() (KeyPair, error) {
	priv, pub, err := curve.GenerateKeyPair()
	return djbKeyPair{djbPrivateKey{priv}, djbPublicKey{pub}}, err
}

func DecodePublicKey(data []byte) (PublicKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("No key type identifier")
	}

	keyType, data := data[0], data[1:]
	switch keyType {
	case djbType:
		if len(data) < djbKeyLen {
			return nil, fmt.Errorf("Bad key length: %v", len(data))
		}

		key := make([]byte, djbKeyLen)
		copy(key, data)
		return djbPublicKey{key}, nil
	default:
		return nil, fmt.Errorf("Bad key type: %v", keyType)
	}
}

func DecodePrivateKey(data []byte) (PrivateKey, error) {
	if len(data) < djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(data))
	}
	key := make([]byte, djbKeyLen)
	copy(key, data)
	return djbPrivateKey{key}, nil
}
