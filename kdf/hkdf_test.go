// Translation of test/kdf/HKDFTest.java
package kdf

import "encoding/hex"
import "testing"
import "bytes"

func TestV3(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	okm, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	output := Version(3).DeriveSaltedSecrets(ikm, salt, info, 42)
	if !bytes.Equal(okm, output) {
		t.Errorf("Incorrect key derivation v3.")
	}
}

func TestLongV3(t *testing.T) {
	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	okm, _ := hex.DecodeString("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")

	output := Version(3).DeriveSaltedSecrets(ikm, salt, info, 82)
	if !bytes.Equal(okm, output) {
		t.Errorf("Incorrect long key derivation v3.")
	}
}

func TestV2(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	okm, _ := hex.DecodeString("6ec2556d5d7b1d81dee4222ad7483695ddc98f4f5fabc0e0205dc2ef8752d41e04e2e21101c68ff09394b8ad0bdcb9609cd4ee82ac13199b4aa9fda899daebec")

	output := Version(2).DeriveSaltedSecrets(ikm, salt, info, 64)
	if !bytes.Equal(okm, output) {
		t.Errorf("Incorrect key derivation v2.")
	}
}
