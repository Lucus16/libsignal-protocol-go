package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/types"
import "github.com/Lucus16/libsignal-protocol-go/ratchet"
import "github.com/Lucus16/libsignal-protocol-go/protocol"

import "bytes"

type Parameters struct {
	OurBaseKey       ecc.Keypair
	OurRatchetKey    ecc.Keypair
	OurIdentityKey   types.IdentityKeypair
	TheirBaseKey     ecc.PublicKey
	TheirRatchetKey  ecc.PublicKey
	TheirIdentityKey types.IdentityKey
}

type aliceParameters struct {
	ourIdentityKey     types.IdentityKeypair
	ourBaseKey         ecc.Keypair
	theirIdentityKey   types.IdentityKey
	theirSignedPrekey  ecc.PublicKey
	theirOneTimePrekey ecc.PublicKey
	theirRatchetKey    ecc.PublicKey
}

type bobParameters struct {
	ourIdentityKey   types.IdentityKeypair
	ourSignedPrekey  ecc.Keypair
	ourOneTimePrekey ecc.Keypair
	ourRatchetKey    ecc.Keypair
	theirIdentityKey types.IdentityKey
	theirBaseKey     ecc.PublicKey
}

func Initialize(session *SessionStructure, params Parameters) {
	if isAlice(params.OurBaseKey, params.TheirBaseKey) {
		alice := aliceParameters{
			ourBaseKey:         params.OurBaseKey,
			ourIdentityKey:     params.OurIdentityKey,
			theirRatchetKey:    params.TheirRatchetKey,
			theirIdentityKey:   params.TheirIdentityKey,
			theirSignedPrekey:  params.TheirBaseKey,
			theirOneTimePrekey: nil,
		}

		aliceInitialize(session, alice)
	} else {
		bob := bobParameters{
			ourIdentityKey:   params.OurIdentityKey,
			ourRatchetKey:    params.OurRatchetKey,
			ourSignedPrekey:  params.OurBaseKey,
			ourOneTimePrekey: nil,
			theirBaseKey:     params.TheirBaseKey,
			theirIdentityKey: params.TheirIdentityKey,
		}

		bobInitialize(session, bob)
	}
}

func aliceInitialize(session *SessionStructure, params aliceParameters) (err error) {
	version := protocol.CurrentVersion
	session.SessionVersion = &version
	session.RemoteIdentityPublic = params.theirIdentityKey.EncodePublicKey()
	session.LocalIdentityPublic = params.ourIdentityKey.EncodePublicKey()

	sendingRatchetKey, err := ecc.GenerateKeypair()
	if err != nil {
		return
	}

	secrets := make([]byte, 0x80)
	secrets = append(secrets, discontinuityBytes()...)

	part, err := params.ourIdentityKey.CalculateAgreement(params.theirSignedPrekey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	part, err = params.ourBaseKey.CalculateAgreement(params.theirIdentityKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	part, err = params.ourBaseKey.CalculateAgreement(params.theirSignedPrekey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	if params.theirOneTimePrekey != nil {
		part, err = params.ourBaseKey.CalculateAgreement(params.theirOneTimePrekey)
		if err != nil {
			return
		}
		secrets = append(secrets, part...)
	}

	rootKey, chainKey := ratchet.CalculateDerivedKeys(secrets)
	newRootKey, newChainKey, err := rootKey.CreateChain(params.theirRatchetKey, sendingRatchetKey)
	if err != nil {
		return
	}

	session.addReceiverChain(params.theirRatchetKey, chainKey)
	session.setSenderChain(sendingRatchetKey, newChainKey)
	session.RootKey = newRootKey.Key()
	return
}

func bobInitialize(session *SessionStructure, params bobParameters) (err error) {
	version := protocol.CurrentVersion
	session.SessionVersion = &version
	session.RemoteIdentityPublic = params.theirIdentityKey.EncodePublicKey()
	session.LocalIdentityPublic = params.ourIdentityKey.EncodePublicKey()

	secrets := make([]byte, 0x80)
	secrets = append(secrets, discontinuityBytes()...)

	part, err := params.ourSignedPrekey.CalculateAgreement(params.theirIdentityKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	part, err = params.ourIdentityKey.CalculateAgreement(params.theirBaseKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	part, err = params.ourSignedPrekey.CalculateAgreement(params.theirBaseKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part...)

	if params.ourOneTimePrekey != nil {
		part, err = params.ourOneTimePrekey.CalculateAgreement(params.theirBaseKey)
		if err != nil {
			return
		}
		secrets = append(secrets, part...)
	}

	rootKey, chainKey := ratchet.CalculateDerivedKeys(secrets)
	session.setSenderChain(params.ourRatchetKey, chainKey)
	session.RootKey = rootKey.Key()
	return
}

func discontinuityBytes() (result []byte) {
	result = make([]byte, 0x20)
	for i := range result {
		result[i] = 0xff
	}
	return
}

func isAlice(ourKey, theirKey ecc.PublicKey) bool {
	return bytes.Compare(ourKey.EncodePublicKey(), theirKey.EncodePublicKey()) < 0
}
