package fingerprint

type Fingerprint struct {
	displayableFingerprint DisplayableFingerprint
	scannableFingerprint   ScannableFingerprint
}

func (fp Fingerprint) DisplayableFingerprint() DisplayableFingerprint {
	return fp.displayableFingerprint
}

func (fp Fingerprint) ScannableFingerprint() ScannableFingerprint {
	return fp.scannableFingerprint
}
