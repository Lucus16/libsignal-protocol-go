package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/ratchet"

type PrekeyRecord = PrekeyRecordStructure
type SessionRecord = SessionStructure
type SignedPrekeyRecord = SignedPrekeyRecordStructure

func NewPrekeyRecord(id uint32, keyPair ecc.KeyPair) PrekeyRecordStructure {
	return PrekeyRecordStructure{
		Id:         &id,
		PublicKey:  keyPair.PublicKey().Encode(),
		PrivateKey: keyPair.PrivateKey().Encode(),
	}
}

func (r PrekeyRecordStructure) GetKeyPair() (keyPair ecc.KeyPair, err error) {
	publicKey, err := ecc.DecodePublicKey(r.PublicKey)
	if err != nil {
		return
	}

	privateKey, err := ecc.DecodePrivateKey(r.PrivateKey)
	if err != nil {
		return
	}

	return ecc.NewKeyPair(privateKey, publicKey), nil
}

func (r PrekeyRecord) setSenderChain(senderRatchetKeyPair ecc.KeyPair, chainKey ratchet.ChainKey) {
	chainKeyStructure := SessionStructure_Chain_ChainKey{
		Index: chainKey.Index(),
		Key:   chainKey.Key(),
	}

	senderChain := SessionStructure_Chain{
		SenderRatchetKey:        senderRatchetKeyPair.PublicKey().Encode(),
		SenderRatchetKeyPrivate: senderRatchetKeyPair.PrivateKey().Encode(),
		ChainKey:                &chainKeyStructure,
	}

	r.SenderChain = &senderChain
}
