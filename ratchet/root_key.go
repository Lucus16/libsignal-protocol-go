package ratchet

import "github.com/Lucus16/libsignal-protocol-go/kdf"
import "github.com/Lucus16/libsignal-protocol-go/ecc"

type RootKey struct {
	kdf kdf.Version
	key []byte
}

func (rk RootKey) Key() []byte {
	return rk.key
}

func (rk RootKey) CreateChain(ourKey ecc.Keypair, theirKey ecc.PublicKey) (RootKey, ChainKey, error) {
	sharedSecret, err := ourKey.CalculateAgreement(theirKey)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	derivedSecret := rk.kdf.DeriveSaltedSecrets(sharedSecret, rk.key, []byte("WhisperRatchet"), 0x40)
	newRootKey := RootKey{rk.kdf, derivedSecret[0x00:0x20]}
	newChainKey := ChainKey{rk.kdf, derivedSecret[0x20:0x40], 0}
	return newRootKey, newChainKey, nil
}

func CalculateDerivedKeys(masterSecret []byte) (RootKey, ChainKey) {
	kdf := kdf.Version(3)
	derivedSecret := kdf.DeriveSecrets(masterSecret, []byte("WhisperText"), 0x40)
	rootKey := RootKey{kdf, derivedSecret[0x00:0x20]}
	chainKey := ChainKey{kdf, derivedSecret[0x20:0x40], 0}
	return rootKey, chainKey
}
