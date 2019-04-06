package protocol

import "github.com/Lucus16/libsignal-protocol-go/consistency"
import "github.com/Lucus16/libsignal-protocol-go/types"
import "github.com/Lucus16/libsignal-protocol-go/util"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "testing"
import "bytes"

func TestConsistency(t *testing.T) {
	devices := make([]types.IdentityKeypair, 3)
	for i := range devices {
		device, err := ecc.GenerateKeypair()
		if err != nil {
			t.Error(err)
		}
		devices[i] = device
	}

	keyList := []types.IdentityKey{
		devices[0],
		devices[1],
		devices[2],
	}

	commitments := make([]consistency.Commitment, 3)
	for i := range commitments {
		util.InsecureShuffle(keyList)
		commitments[i] = consistency.NewCommitment(1, keyList)
	}

	if !bytes.Equal(commitments[0].Serialized, commitments[1].Serialized) ||
		!bytes.Equal(commitments[1].Serialized, commitments[2].Serialized) {
		t.Errorf("Shuffled commitments don't match.")
	}

	messages := make([]ConsistencyMessage, 3)
	for i := range messages {
		message, err := NewConsistencyMessage(commitments[0], devices[i])
		if err != nil {
			t.Error(err)
		}
		messages[i] = message
	}

	receivedMessages := make([]ConsistencyMessage, 3)
	for i := range receivedMessages {
		message, err := DecodeConsistencyMessage(commitments[0], messages[i].Serialized, devices[i])
		if err != nil {
			t.Error(err)
		}
		receivedMessages[i] = message
		if !bytes.Equal(messages[i].Signature.VRFOutput, message.Signature.VRFOutput) {
			t.Errorf("Received vrfOutput doesn't match sent.")
		}
	}

	codes := make([]string, 3)
	for i := range codes {
		codes[i] = consistency.GenerateCode(commitments[i], []consistency.Signature{
			messages[i].Signature,
			receivedMessages[(i+1)%3].Signature,
			receivedMessages[(i+2)%3].Signature,
		})
	}

	if codes[0] != codes[1] || codes[1] != codes[2] {
		t.Errorf("Consistency codes don't match.")
	}
}
