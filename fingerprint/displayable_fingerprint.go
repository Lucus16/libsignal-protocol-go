// Translation of fingerprint/DisplayableFingerprint.java
package fingerprint

import "encoding/binary"
import "strings"
import "fmt"

type DisplayableFingerprint struct {
	localFingerprint  string
	remoteFingerprint string
}

func encodedChunk(bytes []byte) uint64 {
	return (uint64(binary.BigEndian.Uint32(bytes))<<8 | uint64(bytes[4])) % 100000
}

func DisplayFingerprint(fingerprint []byte) string {
	return fmt.Sprintf("%05d%05d%05d%05d%05d%05d",
		encodedChunk(fingerprint[0:]),
		encodedChunk(fingerprint[5:]),
		encodedChunk(fingerprint[10:]),
		encodedChunk(fingerprint[15:]),
		encodedChunk(fingerprint[20:]),
		encodedChunk(fingerprint[25:]))
}

func newDisplayableFingerprint(localFingerprint, remoteFingerprint []byte) DisplayableFingerprint {
	return DisplayableFingerprint{
		DisplayFingerprint(localFingerprint),
		DisplayFingerprint(remoteFingerprint),
	}
}

func (fp DisplayableFingerprint) DisplayText() string {
	if strings.Compare(fp.localFingerprint, fp.remoteFingerprint) < 0 {
		return fp.localFingerprint + fp.remoteFingerprint
	} else {
		return fp.remoteFingerprint + fp.localFingerprint
	}
}
