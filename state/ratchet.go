package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/ratchet"
import "github.com/Lucus16/libsignal-protocol-go/protocol"
import "bytes"

func Initialize(session *SessionStructure, params ratchet.Parameters) {
	if isAlice(params.OurBaseKey, params.TheirBaseKey) {
		aliceInitialize(session, params.Alice())
	} else {
		bobInitialize(session, params.Bob())
	}
}

func aliceInitialize(session *SessionStructure, params ratchet.AliceParameters) (err error) {
	version := protocol.CurrentVersion
	session.SessionVersion = &version
	session.RemoteIdentityPublic = params.TheirIdentityKey.EncodePublicKey()
	session.LocalIdentityPublic = params.OurIdentityKey.EncodePublicKey()

	sendingRatchetKey, err := ecc.GenerateKeypair()
	if err != nil {
		return
	}

	rootKey, chainKey, err := params.CalculateSession()
	if err != nil {
		return
	}

	newRootKey, newChainKey, err := rootKey.CreateChain(sendingRatchetKey, params.TheirRatchetKey)
	if err != nil {
		return
	}

	session.addReceiverChain(params.TheirRatchetKey, chainKey)
	session.setSenderChain(sendingRatchetKey, newChainKey)
	session.RootKey = newRootKey.Key()
	return
}

func bobInitialize(session *SessionStructure, params ratchet.BobParameters) (err error) {
	version := protocol.CurrentVersion
	session.SessionVersion = &version
	session.RemoteIdentityPublic = params.TheirIdentityKey.EncodePublicKey()
	session.LocalIdentityPublic = params.OurIdentityKey.EncodePublicKey()
	rootKey, chainKey, err := params.CalculateSession()
	if err != nil {
		return
	}

	session.setSenderChain(params.OurRatchetKey, chainKey)
	session.RootKey = rootKey.Key()
	return
}

func isAlice(ourKey, theirKey ecc.PublicKey) bool {
	return bytes.Compare(ourKey.EncodePublicKey(), theirKey.EncodePublicKey()) < 0
}
