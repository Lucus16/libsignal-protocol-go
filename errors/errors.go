package errors

import "fmt"

type NoValidSessions []error

func (e NoValidSessions) Error() string {
	return fmt.Sprintf("No valid sessions: %v", e)
}
