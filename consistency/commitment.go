// Translation of devices/DeviceConsistencyCommitment.java
package consistency

import "github.com/Lucus16/libsignal-protocol-go/util"
import "github.com/Lucus16/libsignal-protocol-go/types"
import "encoding/binary"
import "crypto/sha512"

const commitmentVersion = "DeviceConsistencyCommitment_V0"

type Commitment struct {
	generation uint32
	serialized []byte
}

func NewCommitment(generation uint32, identityKeys []types.IdentityKey) Commitment {
	commitments := make([][]byte, len(identityKeys))
	for i, key := range identityKeys {
		commitments[i] = key.EncodePublicKey()
	}
	util.SortByteSlices(commitments)

	digest := sha512.New()
	digest.Write([]byte(commitmentVersion))
	binary.Write(digest, binary.BigEndian, generation)
	util.WriteByteSlices(digest, commitments)

	return Commitment{
		generation,
		digest.Sum(nil),
	}
}

func (c Commitment) Serialized() []byte {
	return c.serialized
}

func (c Commitment) Generation() uint32 {
	return c.generation
}
