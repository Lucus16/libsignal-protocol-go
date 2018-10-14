package libsignal

import "fmt"

type DeviceID int32

type Address struct {
	name     string
	deviceID DeviceID
}

func (a Address) Name() string {
	return a.name
}

func (a Address) DeviceID() DeviceID {
	return a.deviceID
}

func (a Address) String() string {
	return fmt.Sprintf("%s:%d", a.name, a.deviceID)
}
