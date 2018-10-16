// Translation of fingerprint/NumericFingerprintGenerator.java
package fingerprint

import "github.com/Lucus16/libsignal-protocol-go/util"
import sig "github.com/Lucus16/libsignal-protocol-go"
import "crypto/sha512"

const fingerprintVersion = 0

type NumericGenerator struct {
	iterations int
}

func NewNumericGenerator(iterations int) NumericGenerator {
	return NumericGenerator{iterations}
}

func (gen NumericGenerator) Generate(localStableId string, localKeys []sig.IdentityKey,
	remoteStableId string, remoteKeys []sig.IdentityKey) Fingerprint {
	localFingerprint := getFingerprint(gen.iterations, localStableId, localKeys)
	remoteFingerprint := getFingerprint(gen.iterations, remoteStableId, remoteKeys)
	return Fingerprint{
		displayableFingerprint: newDisplayableFingerprint(localFingerprint, remoteFingerprint),
		scannableFingerprint:   newScannableFingerprint(localFingerprint, remoteFingerprint),
	}
}

func getFingerprint(iterations int, stableId string, unsortedKeys []sig.IdentityKey) []byte {
	keys := make([][]byte, len(unsortedKeys))
	for i, key := range unsortedKeys {
		keys[i] = key.Encode()
	}
	util.SortByteSlices(keys)
	publicKey := util.FlattenByteSlices(keys)

	digest := sha512.New()
	util.WriteShort(digest, fingerprintVersion)
	digest.Write(publicKey)
	digest.Write([]byte(stableId))

	var hash []byte
	for i := 0; i < iterations; i++ {
		digest.Write(publicKey)
		hash = digest.Sum(nil)
		digest.Reset()
		digest.Write(hash)
	}
	return hash
}
