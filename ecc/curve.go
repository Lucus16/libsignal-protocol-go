package ecc

import "github.com/Lucus16/curve25519-go"

import "fmt"

const djbKeyLen = 0x20

func GenerateKeypair() (Keypair, error) {
	priv, pub, err := curve.GenerateKeypair()
	return djbKeypair{priv, djbPublicKey{pub}}, err
}

// DecodePublicKey copies the key data in case the slice points to a much larger
// backing array and in order to prevent unintended modification.
func DecodePublicKey(data []byte) (PublicKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("No key type identifier")
	}

	keyType, data := data[0], data[1:]
	switch keyType {
	case djbType:
		if len(data) < djbKeyLen {
			return nil, fmt.Errorf("Bad key length: %d", len(data))
		}

		key := make([]byte, djbKeyLen)
		copy(key, data)
		return djbPublicKey{key}, nil
	default:
		return nil, fmt.Errorf("Bad key type: %d", keyType)
	}
}

// DecodePrivateKey copies the key data in case the slice points to a much
// larger backing array and in order to prevent unintended modification.
func DecodePrivateKey(data []byte) (PrivateKey, error) {
	if len(data) < djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(data))
	}

	privateKey := make([]byte, djbKeyLen)
	copy(privateKey, data)
	publicKey, err := curve.PrivateKey(privateKey).GeneratePublicKey()
	if err != nil {
		return nil, err
	}

	return djbKeypair{privateKey, djbPublicKey{publicKey}}, nil
}

// DecodeKeypair copies the key data in case the slice points to a much larger
// backing array and in order to prevent unintended modification.
func DecodeKeypair(private []byte, public []byte) (Keypair, error) {
	if len(public) < 1 {
		return nil, fmt.Errorf("No key type identifier")
	}

	keyType, public := public[0], public[1:]
	switch keyType {
	case djbType:
		if len(public) < djbKeyLen {
			return nil, fmt.Errorf("Bad public key length: %d", len(public))
		}

		if len(private) < djbKeyLen {
			return nil, fmt.Errorf("Bad private key length: %d", len(private))
		}

		publicKey := make([]byte, djbKeyLen)
		copy(publicKey, public)
		privateKey := make([]byte, djbKeyLen)
		copy(privateKey, private)
		return djbKeypair{privateKey, djbPublicKey{publicKey}}, nil
	default:
		return nil, fmt.Errorf("Bad key type: %d", keyType)
	}
}
