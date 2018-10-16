package state

import "github.com/Lucus16/libsignal-protocol-go"
import "github.com/Lucus16/libsignal-protocol-go/ecc"

const (
	Sending = iota
	Receiving
)

type Direction int

type IdentityKeyStore interface {
	// Local persistent identity.
	LocalKeyPair() ecc.KeyPair

	// Random number between 1 and 16380, generated at install time.
	LocalRegistrationID() int

	// Store a contact as trusted. Return true if an identity was replaced.
	SaveIdentity(address libsignal.Address, key libsignal.IdentityKey) (replaced bool)

	// The convention is that a key is trusted if no key is known for that
	// address yet or if the key matches the key known for that address.
	IsTrusted(address libsignal.Address, key libsignal.IdentityKey, direction Direction) bool

	// Retrieve the key for an address.
	GetIdentity(address libsignal.Address) libsignal.IdentityKey
}

type PrekeyStore interface {
	LoadPrekey(id int) (ok bool, record PrekeyRecord)
	StorePrekey(id int, record PrekeyRecord)
	ContainsPrekey(id int) bool
	RemovePrekey(id int)
}

type SessionStore interface {
	LoadSession(address libsignal.Address) SessionRecord
	SubDeviceSessions(name string) []int32
	StoreSession(address libsignal.Address, record SessionRecord)
	ContainsSession(address libsignal.Address) bool
	DeleteSession(address libsignal.Address)
	DeleteAllSessions(name string)
}

type SignedPrekeyStore interface {
	LoadSignedPrekey(id int) (ok bool, record SignedPrekeyRecord)
	LoadAllSignedPrekeys() []SignedPreKeyRecord
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
