package ratchet

import "github.com/Lucus16/libsignal-protocol-go"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/state"

type Parameters struct {
	OurBaseKey       ecc.KeyPair
	OurRatchetKey    ecc.KeyPair
	OurIdentityKey   libsignal.IdentityKeyPair
	TheirBaseKey     ecc.PublicKey
	TheirRatchetKey  ecc.PublicKey
	TheirIdentityKey libsignal.IdentityKey
}

type aliceParameters struct {
	ourIdentityKey     libsignal.IdentityKeyPair
	ourBaseKey         ecc.KeyPair
	theirIdentityKey   libsignal.IdentityKey
	theirSignedPrekey  ecc.PublicKey
	theirOneTimePrekey ecc.PublicKey
	theirRatchetKey    ecc.PublicKey
}

type bobParameters struct {
	ourIdentityKey   libsignal.IdentityKeyPair
	ourSignedPrekey  ecc.KeyPair
	ourOneTimePrekey ecc.KeyPair
	ourRatchetKey    ecc.KeyPair
	theirIdentityKey libsignal.IdentityKey
	theirBaseKey     ecc.PublicKey
}

func Initialize(session *state.SessionStructure, params Parameters) {
	if isAlice(params.OurBaseKey.PublicKey(), params.TheirBaseKey.PublicKey()) {
		alice := aliceParameters{
			ourBaseKey:         params.OurBaseKey,
			ourIdentityKey:     params.OurIdentityKey,
			theirRatchetKey:    params.theirRatchetKey,
			theirIdentityKey:   params.theirIdentityKey,
			theirSignedPrekey:  params.theirBaseKey,
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

func aliceInitialize(session *state.SessionStructure, params aliceParameters) (err error) {
	session.SessionVersion = protocol.CurrentVersion
	session.RemoteIdentityKey = params.theirIdentityKey
	session.LocalIdentityKey = params.ourIdentityKey.PublicKey()

	sendingRatchetKey = ecc.GenerateKeyPair()
	secrets := make([]byte)
	secrets = append(secrets, discontinuityBytes()...)

	part, err := params.ourIdentityKey().PrivateKey().CalculateAgreement(params.theirSignedPrekey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	part, err = params.ourBaseKey().PrivateKey().CalculateAgreement(params.theirIdentityKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	part, err = params.ourBaseKey().PrivateKey().CalculateAgreement(params.theirSignedPrekey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	if params.theirOneTimePrekey != nil {
		part, err = params.ourBaseKey().PrivateKey().CalculateAgreement(params.theirOneTimePrekey)
		if err != nil {
			return
		}
		secrets = append(secrets, part)
	}

	rootKey, chainKey := calculateDerivedKeys(secrets)
	newRootKey, newChainKey, err := rootKey.createChain(params.theirRatchetKey, sendingRatchetKey)
	if err != nil {
		return
	}

	session.addReceiverChain(params.theirRatchetKey, chainKey)
	session.setSenderChain(sendingRatchetKey, newChainKey)
	session.RootKey = newRootKey
	return
}

func bobInitialize(session *state.SessionStructure, params aliceParameters) (err error) {
	session.SessionVersion = protocol.CurrentVersion
	session.RemoteIdentityKey = params.theirIdentityKey
	session.LocalIdentityKey = params.ourIdentityKey.PublicKey()

	secrets := make([]byte)
	secrets = append(secrets, discontinuityBytes()...)

	part, err := params.ourSignedPrekey().PrivateKey().CalculateAgreement(params.theirIdentityKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	part, err = params.ourIdentityKey().PrivateKey().CalculateAgreement(params.theirBaseKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	part, err = params.ourSignedPrekey().PrivateKey().CalculateAgreement(params.theirBaseKey)
	if err != nil {
		return
	}
	secrets = append(secrets, part)

	if params.theirOneTimePrekey != nil {
		part, err = params.ourBaseKey().PrivateKey().CalculateAgreement(params.theirOneTimePrekey)
		if err != nil {
			return
		}
		secrets = append(secrets, part)
	}

	rootKey, chainKey := calculateDerivedKeys(secrets)
	session.setSenderChain(params.ourRatchetKey, chainKey)
	session.RootKey = rootKey
	return
}

func discontinuityBytes() (result []byte) {
	result := make([]byte, 0x20)
	for i := range result {
		result[i] = 0xff
	}
}

func calculateDerivedKeys(masterSecret []byte) (rootKey RootKey, chainKey ChainKey) {
	kdf := kdf.Version(3)
	derivedSecret := kdf.DeriveSecrets(masterSecret, []byte("WhisperText"), 0x40)
	rootKey = RootKey{kdf, derivedSecret[0x00:0x20]}
	chainKey = ChainKey{kdf, derivedSecret[0x20:0x40], 0}
	return
}

func isAlice(ourKey, theirKey ecc.PublicKey) bool {
	return bytes.Compare(ourKey, theirKey) < 0
}
