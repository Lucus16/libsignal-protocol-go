package fingerprint

import "github.com/Lucus16/libsignal-protocol-go/protos"
import "github.com/golang/protobuf/proto"
import "bytes"
import "fmt"

const scannableFingerprintVersion uint32 = 1
const fingerprintLen = 0x20

type ScannableFingerprint struct {
	protos.CombinedFingerprints
}

type VersionMismatchError struct {
	ExpectedVersion uint32
	OurVersion      uint32
	TheirVersion    uint32
}

func (err VersionMismatchError) Error() string {
	return fmt.Sprintf("Expected fingerprint version %v, got %v and %v.",
		err.ExpectedVersion, err.OurVersion, err.TheirVersion)
}

func newScannableFingerprint(localFingerprint, remoteFingerprint []byte) ScannableFingerprint {
	version := scannableFingerprintVersion
	return ScannableFingerprint{protos.CombinedFingerprints{
		Version: &version,
		LocalFingerprint: &protos.LogicalFingerprint{
			Content: localFingerprint[:fingerprintLen],
		},
		RemoteFingerprint: &protos.LogicalFingerprint{
			Content: remoteFingerprint[:fingerprintLen],
		},
	}}
}

func (fp ScannableFingerprint) isValid() bool {
	return fp.GetVersion() == scannableFingerprintVersion &&
		len(fp.GetLocalFingerprint().GetContent()) == fingerprintLen &&
		len(fp.GetRemoteFingerprint().GetContent()) == fingerprintLen
}

func (a ScannableFingerprint) Matches(b ScannableFingerprint) (bool, error) {
	if !a.isValid() || !b.isValid() {
		return false, VersionMismatchError{
			scannableFingerprintVersion,
			a.GetVersion(),
			b.GetVersion(),
		}
	}
	return bytes.Equal(a.LocalFingerprint.Content, b.RemoteFingerprint.Content) &&
		bytes.Equal(a.RemoteFingerprint.Content, b.LocalFingerprint.Content), nil
}

func (fp ScannableFingerprint) Serialized() ([]byte, error) {
	return proto.Marshal(&fp.CombinedFingerprints)
}
