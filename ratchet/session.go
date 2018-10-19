package ratchet

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/types"

type Parameters struct {
	OurBaseKey       ecc.Keypair
	OurRatchetKey    ecc.Keypair
	OurIdentityKey   types.IdentityKeypair
	TheirBaseKey     ecc.PublicKey
	TheirRatchetKey  ecc.PublicKey
	TheirIdentityKey types.IdentityKey
}

type AliceParameters struct {
	OurIdentityKey     types.IdentityKeypair
	OurBaseKey         ecc.Keypair
	TheirIdentityKey   types.IdentityKey
	TheirSignedPrekey  ecc.PublicKey
	TheirOneTimePrekey ecc.PublicKey
	TheirRatchetKey    ecc.PublicKey
}

type BobParameters struct {
	OurIdentityKey   types.IdentityKeypair
	OurSignedPrekey  ecc.Keypair
	OurOneTimePrekey ecc.Keypair
	OurRatchetKey    ecc.Keypair
	TheirIdentityKey types.IdentityKey
	TheirBaseKey     ecc.PublicKey
}

func (params Parameters) Alice() AliceParameters {
	return AliceParameters{
		OurBaseKey:         params.OurBaseKey,
		OurIdentityKey:     params.OurIdentityKey,
		TheirRatchetKey:    params.TheirRatchetKey,
		TheirIdentityKey:   params.TheirIdentityKey,
		TheirSignedPrekey:  params.TheirBaseKey,
		TheirOneTimePrekey: nil,
	}
}

func (params Parameters) Bob() BobParameters {
	return BobParameters{
		OurIdentityKey:   params.OurIdentityKey,
		OurRatchetKey:    params.OurRatchetKey,
		OurSignedPrekey:  params.OurBaseKey,
		OurOneTimePrekey: nil,
		TheirBaseKey:     params.TheirBaseKey,
		TheirIdentityKey: params.TheirIdentityKey,
	}
}

type secretAccumulator struct {
	secrets []byte
	err     error
}

func (a *secretAccumulator) add(privateKey ecc.PrivateKey, publicKey ecc.PublicKey) {
	if a.err == nil {
		newBytes, err := privateKey.CalculateAgreement(publicKey)
		a.err = err
		a.secrets = append(a.secrets, newBytes...)
	}
}

func (a *secretAccumulator) result() (RootKey, ChainKey, error) {
	if a.err != nil {
		return RootKey{}, ChainKey{}, a.err
	}

	rootKey, chainKey := CalculateDerivedKeys(a.secrets)
	return rootKey, chainKey, nil
}

func (params AliceParameters) CalculateSession() (RootKey, ChainKey, error) {
	accumulator := secretAccumulator{discontinuityBytes(), nil}
	accumulator.add(params.OurIdentityKey, params.TheirSignedPrekey)
	accumulator.add(params.OurBaseKey, params.TheirIdentityKey)
	accumulator.add(params.OurBaseKey, params.TheirSignedPrekey)
	if params.TheirOneTimePrekey != nil {
		accumulator.add(params.OurBaseKey, params.TheirOneTimePrekey)
	}

	return accumulator.result()
}

func (params BobParameters) CalculateSession() (RootKey, ChainKey, error) {
	accumulator := secretAccumulator{discontinuityBytes(), nil}
	accumulator.add(params.OurSignedPrekey, params.TheirIdentityKey)
	accumulator.add(params.OurIdentityKey, params.TheirBaseKey)
	accumulator.add(params.OurSignedPrekey, params.TheirBaseKey)
	if params.OurOneTimePrekey != nil {
		accumulator.add(params.OurOneTimePrekey, params.TheirBaseKey)
	}

	return accumulator.result()
}

func discontinuityBytes() (result []byte) {
	result = make([]byte, 0x20, 0xa0)
	for i := range result {
		result[i] = 0xff
	}
	return
}
