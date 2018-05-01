package libsignal

import "github.com/Lucus16/libsignal-protocol-go/ecc"

type IdentityKey struct {
	ecc.PublicKey
}

type IdentityKeyPair struct {
	ecc.KeyPair
}
