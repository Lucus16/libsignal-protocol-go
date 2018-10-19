package state

import "github.com/Lucus16/libsignal-protocol-go/protocol"
import "github.com/Lucus16/libsignal-protocol-go/ratchet"
import "github.com/Lucus16/libsignal-protocol-go/ecc"

const maxMessageKeys = 2000

type Session = SessionStructure

func (s *Session) setSenderChain(senderRatchetKeypair ecc.Keypair, chainKey ratchet.ChainKey) {
	index := chainKey.Index()
	chainKeyStructure := SessionStructure_Chain_ChainKey{
		Index: &index,
		Key:   chainKey.Key(),
	}

	senderChain := SessionStructure_Chain{
		SenderRatchetKey:        senderRatchetKeypair.EncodePublicKey(),
		SenderRatchetKeyPrivate: senderRatchetKeypair.EncodePrivateKey(),
		ChainKey:                &chainKeyStructure,
	}

	s.SenderChain = &senderChain
}

func (s *Session) addReceiverChain(senderRatchetKey ecc.PublicKey, chainKey ratchet.ChainKey) {
	index := chainKey.Index()
	chainKeyStructure := SessionStructure_Chain_ChainKey{
		Index: &index,
		Key:   chainKey.Key(),
	}

	chain := SessionStructure_Chain{
		SenderRatchetKey: senderRatchetKey.EncodePublicKey(),
		ChainKey:         &chainKeyStructure,
	}

	chains := s.ReceiverChains
	if len(chains) > 4 {
		chains = chains[len(chains)-4:]
	}

	chains = append([]*SessionStructure_Chain{}, chains...)
	chains = append(chains, &chain)
	s.ReceiverChains = chains
}

func (s *Session) decrypt(message protocol.SignalMessage) ([]byte, error) {
	return nil, nil // TODO
}
