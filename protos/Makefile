all: ../state/LocalStorageProtocol.pb.go ../fingerprint/FingerprintProtocol.pb.go WhisperTextProtocol.pb.go

../state/LocalStorageProtocol.pb.go: LocalStorageProtocol.proto
	protoc --go_out=../state LocalStorageProtocol.proto

../fingerprint/FingerprintProtocol.pb.go: FingerprintProtocol.proto
	protoc --go_out=../fingerprint FingerprintProtocol.proto

WhisperTextProtocol.pb.go: WhisperTextProtocol.proto
	protoc --go_out=. WhisperTextProtocol.proto
