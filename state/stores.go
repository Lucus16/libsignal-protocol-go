package state

import "github.com/Lucus16/libsignal-protocol-go/types"
import "github.com/Lucus16/libsignal-protocol-go/ecc"

const (
	Sending = iota
	Receiving
)

type Direction int

type IdentityKeyStore interface {
	// Local persistent identity.
	LocalKeypair() ecc.Keypair

	// Random number between 1 and 16380, generated at install time.
	LocalRegistrationID() int

	// Store a contact as trusted. Return true if an identity was replaced.
	SaveIdentity(address types.Address, key types.IdentityKey) (replaced bool)

	// The convention is that a key is trusted if no key is known for that
	// address yet or if the key matches the key known for that address.
	IsTrusted(address types.Address, key types.IdentityKey, direction Direction) bool

	// Retrieve the key for an address.
	GetIdentity(address types.Address) types.IdentityKey
}

type PrekeyStore interface {
	LoadPrekey(id int) (ok bool, record PrekeyRecord)
	StorePrekey(id int, record PrekeyRecord)
	ContainsPrekey(id int) bool
	RemovePrekey(id int)
}

type SessionStore interface {
	LoadSession(address types.Address) SessionRecord
	SubDeviceSessions(name string) []int32
	StoreSession(address types.Address, record SessionRecord)
	ContainsSession(address types.Address) bool
	DeleteSession(address types.Address)
	DeleteAllSessions(name string)
}

type SignedPrekeyStore interface {
	LoadSignedPrekey(id int) (ok bool, record SignedPrekeyRecord)
	LoadAllSignedPrekeys() []SignedPrekeyRecord
	StoreSignedPrekey(id int, record SignedPrekeyRecord)
	ContainsSignedPrekey(id int) bool
	RemoveSignedPrekey(id int)
}

type SignalProtocolStore interface {
	IdentityKeyStore
	PrekeyStore
	SessionStore
	SignedPrekeyStore
}
