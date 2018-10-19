package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"

type PrekeyRecord = PreKeyRecordStructure

func NewPrekeyRecord(id uint32, keypair ecc.Keypair) PrekeyRecord {
	return PrekeyRecord{
		Id:         &id,
		PublicKey:  keypair.EncodePublicKey(),
		PrivateKey: keypair.EncodePrivateKey(),
	}
}

func (r PrekeyRecord) GetKeypair() (ecc.Keypair, error) {
	return ecc.DecodeKeypair(r.PrivateKey, r.PublicKey)
}

type SignedPrekeyRecord = SignedPreKeyRecordStructure
