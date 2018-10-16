// Translation of kdf/Derived{Message,Root}Secrets.java
package kdf

const MessageSecretsSize = 0x50
const RootSecretsSize = 0x40

func MessageSecrets(keys []byte) (cipherKey []byte, macKey []byte, initVector []byte) {
	return keys[0x00:0x20], keys[0x20:0x40], keys[0x40:0x50]
}

func RootSecrets(keys []byte) (rootKey []byte, chainKey []byte) {
	return keys[0x00:0x20], keys[0x20:0x40]
}
