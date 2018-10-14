package kdf

const DerivedMessageSecretsSize = 0x50
const DerivedRootSecretsSize = 0x40

type DerivedMessageSecrets struct {
	cipherKey  []byte
	macKey     []byte
	initVector []byte
}

func (dms DerivedMessageSecrets) CipherKey() []byte {
	return dms.cipherKey
}

func (dms DerivedMessageSecrets) MacKey() []byte {
	return dms.macKey
}

func (dms DerivedMessageSecrets) InitVector() []byte {
	return dms.initVector
}

func NewDerivedMessageSecrets(keys []byte) DerivedMessageSecrets {
	return DerivedMessageSecrets{
		keys[0x00:0x20],
		keys[0x20:0x40],
		keys[0x40:0x50],
	}
}

type DerivedRootSecrets struct {
	rootKey  []byte
	chainKey []byte
}

func (drs DerivedRootSecrets) RootKey() []byte {
	return drs.rootKey
}

func (drs DerivedRootSecrets) ChainKey() []byte {
	return drs.chainKey
}

func NewDerivedRootSecrets(keys []byte) DerivedRootSecrets {
	return DerivedRootSecrets{
		keys[0x00:0x20],
		keys[0x20:0x40],
	}
}
