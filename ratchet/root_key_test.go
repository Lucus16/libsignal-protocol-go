// Translation of test/ratchet/RootKeyTest.java
package ratchet

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/kdf"

import "encoding/hex"
import "testing"
import "bytes"

func TestRootKeyCreateChain(t *testing.T) {
	rootKeySeed, _ := hex.DecodeString("7ba6debc2bc1bbf91abbc1367404176ca623095b7ec66b45f602d93538942dcc")
	alicePublic, _ := hex.DecodeString("05ee4fa6cdc030df49ecd0ba6cfcffb233d365a27fadbeff77e963fcb16222e13a")
	alicePrivate, _ := hex.DecodeString("216822ec67eb38049ebae7b939baeaebb151bbb32db80fd389245ac37a948e50")
	bobPublic, _ := hex.DecodeString("05abb8eb29cc80b47109a2265abe9798485406e32da268934a9555e84757708a30")
	nextRoot, _ := hex.DecodeString("b114f5de28011985e6eba25d50e7ec41a9b02f5693c5c788a63a06d212a2f731")
	nextChain, _ := hex.DecodeString("9d7d2469bc9ae53ee9805aa3264d2499a3ace80f4ccae2da13430c5c55b5ca5f")

	aliceKeypair, err := ecc.DecodeKeypair(alicePrivate, alicePublic)
	if err != nil {
		t.Error(err)
	}

	bobKey, err := ecc.DecodePublicKey(bobPublic)
	if err != nil {
		t.Error(err)
	}

	rootKey := RootKey{kdf.Version(2), rootKeySeed}
	nextRootKey, nextChainKey, err := rootKey.CreateChain(aliceKeypair, bobKey)

	if !bytes.Equal(nextRootKey.Key(), nextRoot) {
		t.Errorf("Next root key doesn't match.")
	}

	if !bytes.Equal(nextChainKey.Key(), nextChain) {
		t.Errorf("Next chain key doesn't match.")
	}
}
