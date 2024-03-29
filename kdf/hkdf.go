// Translation of kdf/HKDF{,v2,v3}.java
package kdf

import "crypto/sha256"
import "crypto/hmac"
import "fmt"

const hashOutputSize = 0x20

type Version int

func (v Version) iterationOffset() int {
	switch v {
	case 2:
		return 0
	case 3:
		return 1
	default:
		panic(fmt.Sprintf("Unknown kdf version: %d", v))
	}
}

func (v Version) DeriveSecrets(inputKeyMaterial, info []byte, outputLength int) []byte {
	return v.DeriveSaltedSecrets(inputKeyMaterial, make([]byte, hashOutputSize), info, outputLength)
}

func (v Version) DeriveSaltedSecrets(inputKeyMaterial, salt, info []byte, outputLength int) []byte {
	prk := v.extract(salt, inputKeyMaterial)
	return v.expand(prk, info, outputLength)
}

func (v Version) extract(salt, inputKeyMaterial []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(inputKeyMaterial)
	return mac.Sum(nil)
}

func (v Version) expand(prk, info []byte, outputSize int) []byte {
	iterations := (outputSize + hashOutputSize - 1) / hashOutputSize
	var mixin []byte
	var result []byte

	for i := 0; i < iterations; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(mixin)
		mac.Write(info)
		mac.Write([]byte{byte(i + v.iterationOffset())})
		stepResult := mac.Sum(nil)
		result = append(result, stepResult...)
		mixin = stepResult
	}

	return result[:outputSize]
}
