package ratchet

type MessageKeys struct {
	CipherKey  []byte
	MACKey     []byte
	InitVector []byte
	Counter    uint32
}
