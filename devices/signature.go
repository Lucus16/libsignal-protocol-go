package consistency

type Signature struct {
	signature []byte
	vrfOutput []byte
}

func (dcs Signature) Signature() []byte {
	return dcs.signature
}

func (dcs Signature) VrfOutput() []byte {
	return dcs.vrfOutput
}
