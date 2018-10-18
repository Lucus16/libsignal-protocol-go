// Translation of test/ratchet/ChainKeyTest.java
package ratchet

import "github.com/Lucus16/libsignal-protocol-go/kdf"

import "encoding/hex"
import "testing"
import "bytes"

func TestChainKeyDerivationV2(t *testing.T) {
	seed, _ := hex.DecodeString("8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f")
	messageKey, _ := hex.DecodeString("02a9aa6c7dbd64f9d3aa92f92a277bf54609dadf0b00828acfc61e3c724b84a7")
	macKey, _ := hex.DecodeString("bfbe5efb603030526742e3ee89c7024e884e440f1ff376bb2317b2d64deb7c83")
	nextChainKey, _ := hex.DecodeString("28e8f8fee54b801eef7c5cfb2f17f32c7b334485bbb70fac6ec10342a246d15d")
	chainKey := ChainKey{kdf.Version(2), seed, 0}

	if !bytes.Equal(chainKey.MessageKeys().CipherKey, messageKey) {
		t.Errorf("Cipher key doesn't match message key.")
	}

	if !bytes.Equal(chainKey.MessageKeys().MACKey, macKey) {
		t.Errorf("Message key doesn't match.")
	}

	if !bytes.Equal(chainKey.NextChainKey().Key(), nextChainKey) {
		t.Errorf("Next chain key doesn't match.")
	}
}

func TestChainKeyDerivationV3(t *testing.T) {
	seed, _ := hex.DecodeString("8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f")
	messageKey, _ := hex.DecodeString("bf51e9d75e0e31031051f82a2491ffc084fa298b7793bd9db620056febf45217")
	macKey, _ := hex.DecodeString("c6c77d6a73a354337a56435e34607dfe48e3ace14e77314dc6abc172e7a7030b")
	nextChainKey, _ := hex.DecodeString("28e8f8fee54b801eef7c5cfb2f17f32c7b334485bbb70fac6ec10342a246d15d")
	chainKey := ChainKey{kdf.Version(3), seed, 0}

	if !bytes.Equal(chainKey.MessageKeys().CipherKey, messageKey) {
		t.Errorf("Cipher key doesn't match message key.")
	}

	if !bytes.Equal(chainKey.MessageKeys().MACKey, macKey) {
		t.Errorf("Message key doesn't match.")
	}

	if !bytes.Equal(chainKey.NextChainKey().Key(), nextChainKey) {
		t.Errorf("Next chain key doesn't match.")
	}
}
