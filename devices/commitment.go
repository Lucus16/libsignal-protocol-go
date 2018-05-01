package consistency

import "github.com/Lucus16/libsignal-protocol-go/util"
import sig "github.com/Lucus16/libsignal-protocol-go"
import "encoding/binary"
import "crypto/sha512"

const commitmentVersion = "DeviceConsistencyCommitment_V0"

type Commitment struct {
	generation uint32
	serialized []byte
}

func NewCommitment(generation uint32, identityKeys []sig.IdentityKey) Commitment {
	commitments := make([][]byte, len(identityKeys))
	for i, key := range identityKeys {
		commitments[i] = key.Encode()
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

func (dcc Commitment) Serialized() []byte {
	return dcc.serialized
}

func (dcc Commitment) Generation() uint32 {
	return dcc.generation
}
