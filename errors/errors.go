package errors

import "fmt"

type NoValidSessions []error
type InvalidVersion byte
type InvalidMessage string

func (e NoValidSessions) Error() string {
	return fmt.Sprintf("No valid sessions: %v", e)
}

func (e InvalidVersion) Error() string {
	return fmt.Sprintf("Invalid version: %d", e)
}

func (e InvalidMessage) Error() string {
	return string(e)
}
