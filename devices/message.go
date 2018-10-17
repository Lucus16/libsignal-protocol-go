package consistency

import "github.com/Lucus16/libsignal-protocol-go/protocol"
import sig "github.com/Lucus16/libsignal-protocol-go"
import "github.com/golang/protobuf/proto"

type Message struct {
	signature  Signature
	generation uint32
	serialized []byte
}

func (m Message) Signature() Signature {
	return m.signature
}

func (m Message) Generation() uint32 {
	return m.generation
}

func (m Message) Serialized() []byte {
	return m.serialized
}

func MessageFromKeyPair(commitment Commitment, keyPair sig.IdentityKeyPair) (result Message, err error) {
	signatureBytes, err := keyPair.PrivateKey().CalculateVrfSignature(commitment.Serialized())
	if err != nil {
		return
	}
	vrfOutputBytes, err := keyPair.PublicKey().VerifyVrfSignature(commitment.Serialized(), signatureBytes)
	if err != nil {
		return
	}

	signature := Signature{
		signature: signatureBytes,
		vrfOutput: vrfOutputBytes,
	}
	commitmentGeneration := commitment.Generation()
	codeMessage := protocol.DeviceConsistencyCodeMessage{
		Generation: &commitmentGeneration,
		Signature:  signature.Signature(),
	}

	codeMessageBytes, err := proto.Marshal(&codeMessage)
	if err != nil {
		return
	}

	return Message{
		generation: commitment.Generation(),
		signature:  signature,
		serialized: codeMessageBytes,
	}, nil
}

func MessageFromSerialized(commitment Commitment, serialized []byte, key sig.IdentityKey) (result Message, err error) {
	codeMessage := &protocol.DeviceConsistencyCodeMessage{}
	err = proto.Unmarshal(serialized, codeMessage)
	if err != nil {
		return
	}
	vrfOutputBytes, err := key.VerifyVrfSignature(commitment.Serialized(), codeMessage.Signature)
	if err != nil {
		return
	}

	return Message{
		generation: *codeMessage.Generation,
		signature: Signature{
			signature: codeMessage.Signature,
			vrfOutput: vrfOutputBytes,
		},
		serialized: serialized,
	}, nil
}
