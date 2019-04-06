package protocol

import "github.com/Lucus16/libsignal-protocol-go/consistency"
import "github.com/Lucus16/libsignal-protocol-go/protos"
import "github.com/Lucus16/libsignal-protocol-go/types"
import "github.com/golang/protobuf/proto"

type ConsistencyMessage struct {
	Signature  consistency.Signature
	Generation uint32
	Serialized []byte
}

func NewConsistencyMessage(commitment consistency.Commitment, keypair types.IdentityKeypair) (ConsistencyMessage, error) {
	signatureBytes, err := keypair.CalculateVrfSignature(commitment.Serialized)
	if err != nil {
		return ConsistencyMessage{}, err
	}

	vrfOutputBytes, err := keypair.VerifyVrfSignature(commitment.Serialized, signatureBytes)
	if err != nil {
		return ConsistencyMessage{}, err
	}

	signature := consistency.Signature{
		Signature: signatureBytes,
		VRFOutput: vrfOutputBytes,
	}

	generation := commitment.Generation
	codeMessage := protos.DeviceConsistencyCodeMessage{
		Generation: &generation,
		Signature:  signatureBytes,
	}

	protoBytes, err := proto.Marshal(&codeMessage)
	if err != nil {
		return ConsistencyMessage{}, err
	}

	return ConsistencyMessage{
		Generation: commitment.Generation,
		Signature:  signature,
		Serialized: protoBytes,
	}, nil
}

func DecodeConsistencyMessage(commitment consistency.Commitment, serialized []byte,
	key types.IdentityKey) (ConsistencyMessage, error) {
	codeMessage := &protos.DeviceConsistencyCodeMessage{}
	err := proto.Unmarshal(serialized, codeMessage)
	if err != nil {
		return ConsistencyMessage{}, err
	}

	vrfOutputBytes, err := key.VerifyVrfSignature(commitment.Serialized, codeMessage.Signature)
	if err != nil {
		return ConsistencyMessage{}, err
	}

	return ConsistencyMessage{
		Generation: *codeMessage.Generation,
		Signature: consistency.Signature{
			Signature: codeMessage.Signature,
			VRFOutput: vrfOutputBytes,
		},
		Serialized: serialized,
	}, nil
}
