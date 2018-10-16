// Translation of devices/DeviceConsistencySignature.java
package consistency

type Signature struct {
	signature []byte
	vrfOutput []byte
}

func (s Signature) Signature() []byte {
	return s.signature
}

func (s Signature) VrfOutput() []byte {
	return s.vrfOutput
}
