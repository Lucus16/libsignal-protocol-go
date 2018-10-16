package state

func NewPrekeyRecord(id int, keyPair ecc.KeyPair) {
	return PreKeyRecordStructure{
		Id:         id,
		PublicKey:  keyPair.PublicKey(),
		PrivateKey: keyPair.PrivateKey(),
	}
}

func (r PreKeyRecordStructure) GetKeyPair() (keyPair ecc.KeyPair, err error) {
	publicKey, err := ecc.DecodePublicKey(r.PublicKey)
	if err != nil {
		return
	}

	privateKey, err := ecc.DecodePrivateKey(r.PrivateKey)
	if err != nil {
		return
	}

	return ecc.KeyPair{privateKey, publicKey}, nil
}
