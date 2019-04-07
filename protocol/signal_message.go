package protocol

import "github.com/Lucus16/libsignal-protocol-go/protos"
import "github.com/Lucus16/libsignal-protocol-go/errors"
import "github.com/Lucus16/libsignal-protocol-go/types"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/golang/protobuf/proto"
import "crypto/sha256"
import "crypto/hmac"
import "bytes"

const macLength = 8

type SignalMessage struct {
	Version          byte
	SenderRatchetKey ecc.PublicKey
	Counter          uint32
	PreviousCounter  uint32
	Ciphertext       []byte
	serialized       []byte
}

func NewSignalMessage(messageVersion byte, macKey []byte,
	senderRatchetKey ecc.PublicKey,
	counter, previousCounter uint32, ciphertext []byte,
	sender, receiver types.IdentityKey) (SignalMessage, error) {

	protoBytes, err := proto.Marshal(&protos.SignalMessage{
		RatchetKey:      senderRatchetKey.EncodePublicKey(),
		Counter:         &counter,
		PreviousCounter: &previousCounter,
		Ciphertext:      ciphertext,
	})
	if err != nil {
		return SignalMessage{}, err
	}

	version := messageVersion<<4 | byte(CurrentVersion)
	serialized := append([]byte{version}, protoBytes...)
	mac := getMAC(sender, receiver, macKey, serialized)
	serialized = append(serialized, mac...)

	return SignalMessage{
		Version:          version,
		serialized:       serialized,
		SenderRatchetKey: senderRatchetKey,
		Counter:          counter,
		PreviousCounter:  previousCounter,
		Ciphertext:       ciphertext,
	}, nil
}

func DecodeSignalMessage(serialized []byte) (SignalMessage, error) {
	macStart := len(serialized) - macLength
	if macStart < 1 {
		return SignalMessage{}, errors.InvalidMessage("Message too small")
	}

	version := serialized[0] >> 4
	if uint32(version) != CurrentVersion {
		return SignalMessage{}, errors.InvalidVersion(version)
	}

	var message protos.SignalMessage
	err := proto.Unmarshal(serialized[1:macStart], &message)
	if err != nil {
		return SignalMessage{}, err
	}

	if message.Ciphertext == nil || message.Counter == nil ||
		message.RatchetKey == nil {
		return SignalMessage{}, errors.InvalidMessage("Incomplete message")
	}

	senderRatchetKey, err := ecc.DecodePublicKey(message.GetRatchetKey())
	if err != nil {
		return SignalMessage{}, err
	}

	return SignalMessage{
		serialized:       serialized,
		Version:          version,
		SenderRatchetKey: senderRatchetKey,
		Counter:          message.GetCounter(),
		PreviousCounter:  message.GetPreviousCounter(),
		Ciphertext:       message.GetCiphertext(),
	}, nil
}

func (m SignalMessage) VerifyMAC(sender, receiver types.IdentityKey, macKey []byte) error {
	macStart := len(m.serialized) - macLength
	ourMAC := getMAC(sender, receiver, macKey, m.serialized[:macStart])
	theirMAC := m.serialized[macStart:]
	if !bytes.Equal(ourMAC, theirMAC) {
		return errors.InvalidMessage("Bad MAC")
	}
	return nil
}

func getMAC(sender, receiver types.IdentityKey, macKey []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(sender.EncodePublicKey())
	mac.Write(receiver.EncodePublicKey())
	mac.Write(data)
	fullMac := mac.Sum(nil)
	return fullMac[:macLength]
}

func (m SignalMessage) Serialize() []byte {
	return m.serialized
}
