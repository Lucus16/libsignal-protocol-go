package protocol

import "github.com/Lucus16/libsignal-protocol-go/protos"
import "github.com/Lucus16/libsignal-protocol-go/errors"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/golang/protobuf/proto"

type KeyDistributionMessage struct {
	Id         uint32
	Iteration  uint32
	ChainKey   []byte
	SigningKey ecc.PublicKey
	Serialized []byte
}

func NewKeyDistributionMessage(id uint32, iteration uint32, chainKey []byte,
	signingKey ecc.PublicKey) (KeyDistributionMessage, error) {

	version := byte((CurrentVersion << 4) | CurrentVersion)
	protoBytes, err := proto.Marshal(&protos.SenderKeyDistributionMessage{
		Id:         &id,
		Iteration:  &iteration,
		ChainKey:   chainKey,
		SigningKey: signingKey.EncodePublicKey(),
	})
	if err != nil {
		return KeyDistributionMessage{}, err
	}

	return KeyDistributionMessage{
		Id:         id,
		Iteration:  iteration,
		ChainKey:   chainKey,
		SigningKey: signingKey,
		Serialized: append([]byte{version}, protoBytes...),
	}, nil
}

func DecodeKeyDistributionMessage(serialized []byte) (KeyDistributionMessage, error) {
	version := serialized[0] >> 4
	if uint32(version) != CurrentVersion {
		return KeyDistributionMessage{}, errors.InvalidVersion(version)
	}

	var message protos.SenderKeyDistributionMessage
	err := proto.Unmarshal(serialized[1:], &message)
	if err != nil {
		return KeyDistributionMessage{}, err
	}

	if message.Id == nil || message.Iteration == nil ||
		message.ChainKey == nil || message.SigningKey == nil {
		return KeyDistributionMessage{}, errors.InvalidMessage("incomplete message")
	}

	signingKey, err := ecc.DecodePublicKey(message.SigningKey)
	if err != nil {
		return KeyDistributionMessage{}, err
	}

	return KeyDistributionMessage{
		Serialized: serialized,
		Id:         *message.Id,
		Iteration:  *message.Iteration,
		ChainKey:   message.ChainKey,
		SigningKey: signingKey,
	}, nil
}
