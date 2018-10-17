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

func (rk RootKey) createChain(theirKey ecc.PublicKey, ourKey ecc.KeyPair) (newRootKey RootKey, newChainKey ChainKey, err error) {
	sharedSecret, err := ourKey.PrivateKey().CalculateAgreement(theirKey)
	if err != nil {
		return
	}

	derivedSecretBytes := rk.kdf.DeriveSaltedSecrets(sharedSecret, rk.key, []byte("WhisperRatchet"), kdf.RootSecretsSize)
	rootKey, chainKey := kdf.RootSecrets(derivedSecretBytes)

	newRootKey = RootKey{rk.kdf, rootKey}
	newChainKey = ChainKey{rk.kdf, chainKey, 0}

	return
}
