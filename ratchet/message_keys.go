package ratchet

type MessageKeys struct {
	cipherKey  []byte
	macKey     []byte
	initVector []byte
	counter    int
}

func (keys MessageKeys) CipherKey() []byte {
	return keys.cipherKey
}

func (keys MessageKeys) MacKey() []byte {
	return keys.macKey
}

func (keys MessageKeys) InitVector() []byte {
	return keys.initVector
}

func (keys MessageKeys) Counter() int {
	return keys.counter
}
