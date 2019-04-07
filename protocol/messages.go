package protocol

const CurrentVersion uint32 = 3

type Message interface {
	Serialize() []byte
}
