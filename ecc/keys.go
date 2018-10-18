package ecc

type PrivateKey interface {
	EncodePrivateKey() []byte
	CalculateAgreement(publicKey PublicKey) ([]byte, error)
	CalculateSignature(message []byte) ([]byte, error)
	CalculateVrfSignature(message []byte) ([]byte, error)
}

type PublicKey interface {
	EncodePublicKey() []byte
	VerifySignature(message []byte, signature []byte) (ok bool, err error)
	VerifyVrfSignature(message []byte, signature []byte) (vrfOutput []byte, err error)
}

type Keypair interface {
	PrivateKey
	PublicKey
}
