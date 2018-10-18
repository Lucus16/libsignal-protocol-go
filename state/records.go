package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/Lucus16/libsignal-protocol-go/ratchet"

type PrekeyRecord = PrekeyRecordStructure
type SessionRecord = SessionStructure
type SignedPrekeyRecord = SignedPrekeyRecordStructure

func NewPrekeyRecord(id uint32, keypair ecc.Keypair) PrekeyRecord {
	return PrekeyRecord{
		Id:         &id,
		PublicKey:  keypair.EncodePublicKey(),
		PrivateKey: keypair.EncodePrivateKey(),
	}
}

func (r PrekeyRecord) GetKeypair() (keypair ecc.Keypair, err error) {
	return ecc.DecodeKeypair(r.PrivateKey, r.PublicKey)
}

func (r PrekeyRecord) setSenderChain(senderRatchetKeypair ecc.Keypair, chainKey ratchet.ChainKey) {
	index := chainKey.Index()
	chainKeyStructure := SessionStructure_Chain_ChainKey{
		Index: &index,
		Key:   chainKey.Key(),
	}

	senderChain := SessionStructure_Chain{
		SenderRatchetKey:        senderRatchetKeypair.EncodePublicKey(),
		SenderRatchetKeyPrivate: senderRatchetKeypair.EncodePrivateKey(),
		ChainKey:                &chainKeyStructure,
	}

	r.SenderChain = &senderChain
}
