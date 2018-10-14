package ecc

type PrivateKey interface {
	Encode() (data []byte)
	CalculateAgreement(publicKey PublicKey) (agreement []byte, err error)
	CalculateSignature(message []byte) (signature []byte, err error)
	CalculateVrfSignature(message []byte) (signature []byte, err error)
}

type PublicKey interface {
	Encode() (data []byte)
	VerifySignature(message []byte, signature []byte) (ok bool, err error)
	VerifyVrfSignature(message []byte, signature []byte) (vrfOutput []byte, err error)
}

type KeyPair interface {
	PrivateKey() PrivateKey
	PublicKey() PublicKey
}
