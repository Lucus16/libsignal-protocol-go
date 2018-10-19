package ratchet

import "github.com/Lucus16/libsignal-protocol-go/kdf"

import "crypto/sha256"
import "crypto/hmac"

var messageKeySeed = []byte{0x01}
var chainKeySeed = []byte{0x02}

type ChainKey struct {
	kdf   kdf.Version
	key   []byte
	index uint32
}

func (key ChainKey) Key() []byte {
	return key.key
}

func (key ChainKey) Index() uint32 {
	return key.index
}

func (key ChainKey) NextChainKey() ChainKey {
	return ChainKey{key.kdf, key.getBaseMaterial(chainKeySeed), key.index + 1}
}

func (key ChainKey) MessageKeys() MessageKeys {
	inputKeyMaterial := key.getBaseMaterial(messageKeySeed)
	derivedSecret := key.kdf.DeriveSecrets(inputKeyMaterial, []byte("WhisperMessageKeys"), 0x50)
	return MessageKeys{
		CipherKey:  derivedSecret[0x00:0x20],
		MACKey:     derivedSecret[0x20:0x40],
		InitVector: derivedSecret[0x40:0x50],
		Counter:    key.index,
	}
}

func (key ChainKey) getBaseMaterial(seed []byte) []byte {
	mac := hmac.New(sha256.New, key.key)
	mac.Write(seed)
	return mac.Sum(nil)
}
