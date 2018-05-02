package kdf

const DerivedMessageSecretsSize = 0x50
const DerivedRootSecretsSize = 0x40

type DerivedMessageSecrets struct {
	CipherKey  []byte
	MacKey     []byte
	InitVector []byte
}

func NewDerivedMessageSecrets(keys []byte) DerivedMessageSecrets {
	return DerivedMessageSecrets{
		keys[0x00:0x20],
		keys[0x20:0x40],
		keys[0x40:0x50],
	}
}

type DerivedRootSecrets struct {
	RootKey  []byte
	ChainKey []byte
}

func NewDerivedRootSecrets(keys []byte) DerivedRootSecrets {
	return DerivedRootSecrets{
		keys[0x00:0x20],
		keys[0x20:0x40],
	}
}
