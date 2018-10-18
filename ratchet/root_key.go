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

func (rk RootKey) CreateChain(theirKey ecc.PublicKey, ourKey ecc.Keypair) (newRootKey RootKey, newChainKey ChainKey, err error) {
	sharedSecret, err := ourKey.CalculateAgreement(theirKey)
	if err != nil {
		return
	}

	derivedSecretBytes := rk.kdf.DeriveSaltedSecrets(sharedSecret, rk.key, []byte("WhisperRatchet"), kdf.RootSecretsSize)
	rootKey, chainKey := kdf.RootSecrets(derivedSecretBytes)

	newRootKey = RootKey{rk.kdf, rootKey}
	newChainKey = ChainKey{rk.kdf, chainKey, 0}

	return
}

func CalculateDerivedKeys(masterSecret []byte) (rootKey RootKey, chainKey ChainKey) {
	kdf := kdf.Version(3)
	derivedSecret := kdf.DeriveSecrets(masterSecret, []byte("WhisperText"), 0x40)
	rootKey = RootKey{kdf, derivedSecret[0x00:0x20]}
	chainKey = ChainKey{kdf, derivedSecret[0x20:0x40], 0}
	return
}
