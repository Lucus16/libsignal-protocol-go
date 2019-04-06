package consistency

import "github.com/Lucus16/libsignal-protocol-go/fingerprint"
import "github.com/Lucus16/libsignal-protocol-go/util"
import "crypto/sha512"

const codeVersion = 0

type Signature struct {
	Signature []byte
	VRFOutput []byte
}

func GenerateCode(commitment Commitment, signatures []Signature) string {
	sortedSignatures := make([][]byte, len(signatures))
	for i, signature := range signatures {
		sortedSignatures[i] = signature.VRFOutput
	}
	util.SortByteSlices(sortedSignatures)

	digest := sha512.New()
	util.WriteShort(digest, codeVersion)
	digest.Write(commitment.Serialized)
	util.WriteByteSlices(digest, sortedSignatures)

	hash := digest.Sum(nil)
	return fingerprint.DisplayFingerprint(hash)[:6]
}
