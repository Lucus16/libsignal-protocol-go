package state

import "github.com/Lucus16/libsignal-protocol-go/ecc"

import "bytes"

type SessionRecord []*Session

const archivedSessionsMaxLength = 40

func NewSessionRecord(session *Session) SessionRecord {
	return SessionRecord{session}
}

func (r SessionRecord) HasSession(version uint32, aliceBaseKey ecc.PublicKey) bool {
	aliceBaseBytes := aliceBaseKey.EncodePublicKey()
	for _, session := range r {
		if *session.SessionVersion == version && bytes.Equal(aliceBaseBytes, session.AliceBaseKey) {
			return true
		}
	}

	return false
}

func (r SessionRecord) FreshSession() SessionRecord {
	if r.fresh {
		return r
	}

	if len(r) > archivedSessionsMaxLength {
		r = r[:archivedSessionsMaxLength]
	}

	return append([]*Session{&Session{}}, r...)
}

func (r SessionRecord) BumpSession(index int) SessionRecord {
	return append(append([]*Session{r[index]}, r[:index]...), r[index+1:]...)
}

func (r *SessionRecord) Decrypt(message SignalMessage) ([]byte, error) {
	var errs []error
	for i, session := range *r {
		plaintext, err := session.Decrypt(message)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		bumped := r.BumpSession(i)
		r = &bumped
		return plaintext, nil
	}

	return nil, types.NoValidSessionsError(errs)
}
