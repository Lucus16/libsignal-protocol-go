package state

import "github.com/Lucus16/libsignal-protocol-go/protocol"
import "github.com/Lucus16/libsignal-protocol-go/errors"
import "github.com/Lucus16/libsignal-protocol-go/ecc"
import "github.com/golang/protobuf/proto"
import "bytes"

type SessionRecord struct {
	sessions []*Session
}

const archivedSessionsMaxLength = 40

func NewSessionRecord(session *Session) SessionRecord {
	return SessionRecord{[]*Session{session}}
}

func DecodeSessionRecord(serialized []byte) (SessionRecord, error) {
	var structure RecordStructure
	err := proto.Unmarshal(serialized, &structure)
	if err != nil {
		return SessionRecord{}, err
	}

	return SessionRecord{
		append([]*Session{structure.CurrentSession}, structure.PreviousSessions...),
	}, nil
}

func (r SessionRecord) Encode() ([]byte, error) {
	structure := RecordStructure{
		CurrentSession:   r.sessions[0],
		PreviousSessions: r.sessions[1:],
	}

	return proto.Marshal(&structure)
}

func (r SessionRecord) HasSession(version uint32, aliceBaseKey ecc.PublicKey) bool {
	aliceBaseBytes := aliceBaseKey.EncodePublicKey()
	for _, session := range r.sessions {
		if session.GetSessionVersion() == version &&
			bytes.Equal(aliceBaseBytes, session.GetAliceBaseKey()) {
			return true
		}
	}

	return false
}

func (r SessionRecord) CurrentSession() *Session {
	return r.sessions[0]
}

func (r *SessionRecord) EnsureSession() {
	if len(r.sessions) == 0 {
		r.sessions = []*Session{&Session{}}
	}
}

func (r *SessionRecord) PushSession() {
	if len(r.sessions) > archivedSessionsMaxLength {
		r.sessions = r.sessions[:archivedSessionsMaxLength]
	}

	r.sessions = append([]*Session{&Session{}}, r.sessions...)
}

func (r *SessionRecord) Decrypt(message protocol.SignalMessage) ([]byte, error) {
	var errs []error
	for i, session := range r.sessions {
		newSession := *session
		plaintext, err := newSession.decrypt(message)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		sessions := append([]*Session{&newSession}, r.sessions[:i]...)
		r.sessions = append(sessions, r.sessions[i+1:]...)
		return plaintext, nil
	}

	return nil, errors.NoValidSessions(errs)
}
