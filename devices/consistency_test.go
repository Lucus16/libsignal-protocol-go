// Translation of test/devices/DeviceConsistencyTest.java
package consistency

import "github.com/Lucus16/libsignal-protocol-go/util"
import sig "github.com/Lucus16/libsignal-protocol-go"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "testing"
import "bytes"

func TestConsistency(t *testing.T) {
	devices := make([]sig.IdentityKeyPair, 3)
	for i := range devices {
		device, err := ecc.GenerateKeyPair()
		if err != nil {
			t.Error(err)
		}
		devices[i] = sig.IdentityKeyPair{device}
	}

	keyList := []sig.IdentityKey{
		sig.IdentityKey{devices[0].PublicKey()},
		sig.IdentityKey{devices[1].PublicKey()},
		sig.IdentityKey{devices[2].PublicKey()},
	}

	commitments := make([]Commitment, 3)
	for i := range commitments {
		util.InsecureShuffle(keyList)
		commitments[i] = NewCommitment(1, keyList)
	}

	if !bytes.Equal(commitments[0].Serialized(), commitments[1].Serialized()) ||
		!bytes.Equal(commitments[1].Serialized(), commitments[2].Serialized()) {
		t.Errorf("Shuffled commitments don't match.")
	}

	messages := make([]Message, 3)
	for i := range messages {
		message, err := MessageFromKeyPair(commitments[0], devices[i])
		if err != nil {
			t.Error(err)
		}
		messages[i] = message
	}

	receivedMessages := make([]Message, 3)
	for i := range receivedMessages {
		message, err := MessageFromSerialized(commitments[0], messages[i].Serialized(),
			sig.IdentityKey{devices[i].PublicKey()})
		if err != nil {
			t.Error(err)
		}
		receivedMessages[i] = message
		if !bytes.Equal(messages[i].Signature().VrfOutput(), message.Signature().VrfOutput()) {
			t.Errorf("Received vrfOutput doesn't match sent.")
		}
	}

	codes := make([]string, 3)
	for i := range codes {
		codes[i] = GenerateCode(commitments[i], []Signature{
			messages[i].Signature(),
			receivedMessages[(i+1)%3].Signature(),
			receivedMessages[(i+2)%3].Signature(),
		})
	}

	if codes[0] != codes[1] || codes[1] != codes[2] {
		t.Errorf("Consistency codes don't match.")
	}
}
