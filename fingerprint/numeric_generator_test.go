package fingerprint

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import sig "github.com/Lucus16/libsignal-protocol-go"
import "encoding/hex"
import "testing"
import "bytes"

var (
	aliceIdentity, _             = hex.DecodeString("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
	bobIdentity, _               = hex.DecodeString("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
	displayableFingerprint       = "300354477692869396892869876765458257569162576843440918079131"
	aliceScannableFingerprint, _ = hex.DecodeString("080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d")
	bobScannableFingerprint, _   = hex.DecodeString("080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df")
)

func TestVectors(t *testing.T) {
	eccKey, err := ecc.DecodePublicKey(aliceIdentity)
	if err != nil {
		t.Error(err)
	}
	aliceKey := sig.IdentityKey{eccKey}
	eccKey, err = ecc.DecodePublicKey(bobIdentity)
	if err != nil {
		t.Error(err)
	}
	bobKey := sig.IdentityKey{eccKey}

	generator := NewNumericGenerator(5200)
	aliceFingerprint := generator.Generate(
		"+14152222222", []sig.IdentityKey{aliceKey},
		"+14153333333", []sig.IdentityKey{bobKey})
	bobFingerprint := generator.Generate(
		"+14153333333", []sig.IdentityKey{bobKey},
		"+14152222222", []sig.IdentityKey{aliceKey})

	if aliceFingerprint.DisplayableFingerprint().DisplayText() != displayableFingerprint ||
		bobFingerprint.DisplayableFingerprint().DisplayText() != displayableFingerprint {
		t.Errorf("Incorrect displayable fingerprint.\n%v\n%v",
			aliceFingerprint.DisplayableFingerprint().DisplayText(),
			displayableFingerprint)
	}

	aliceSerializedFingerprint, err := aliceFingerprint.ScannableFingerprint().Serialized()
	if err != nil {
		t.Error(err)
	}
	bobSerializedFingerprint, err := bobFingerprint.ScannableFingerprint().Serialized()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(aliceSerializedFingerprint, aliceScannableFingerprint) ||
		!bytes.Equal(bobSerializedFingerprint, bobScannableFingerprint) {
		t.Errorf("Incorrect scannable fingerprint.\n%x\n%x",
			aliceSerializedFingerprint, aliceScannableFingerprint)
	}
}
