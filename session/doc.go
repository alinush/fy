// Package session provides high-level APIs for threshold signature ceremonies.
// It supports two protocols:
//
//   - FROST: Schnorr-based threshold signatures (generic over curves)
//   - DKLS23: Paillier-free threshold ECDSA (secp256k1)
//
// The session package is designed for application developers who want to
// integrate threshold signatures without understanding every protocol detail.
// For full control, use the [frost], [dkls23/dkg], and [dkls23/sign] packages
// directly.
//
// # FROST DKG Ceremony
//
// A distributed key generation (DKG) ceremony creates key shares for all
// participants. Each participant runs the same code independently:
//
//	// Create participant state
//	p, err := session.NewParticipant(group, threshold, total, myID)
//	if err != nil {
//		return err
//	}
//
//	// Generate round 1 messages
//	r1, err := p.GenerateRound1(rand.Reader, allParticipantIDs)
//	if err != nil {
//		return err
//	}
//
//	// Broadcast r1.Broadcast to all participants
//	// Send r1.PrivateShares[id] to each participant over secure channel
//
//	// After receiving messages from all other participants:
//	result, err := p.ProcessRound1(&session.Round1Input{
//		Broadcasts:    receivedBroadcasts,
//		PrivateShares: receivedShares,
//	})
//
//	// Store result.KeyShare securely
//
// # FROST Signing
//
// Signing uses a session-based API that ensures nonces are never reused:
//
//	// Create a signing session (generates nonces internally)
//	sess, err := p.NewSigningSession(rand.Reader, message)
//	if err != nil {
//		return err
//	}
//
//	// Broadcast sess.Commitment() to other signers
//	// Collect commitments from other signers
//
//	// Produce signature share (consumes the session)
//	share, err := sess.Sign(allCommitments)
//	if err != nil {
//		return err
//	}
//
//	// Coordinator aggregates shares
//	sig, err := session.Aggregate(frost, message, allCommitments, allShares)
//
// The SigningSession is designed to be used exactly once. Calling Sign a
// second time returns an error, preventing accidental nonce reuse which
// would compromise security.
//
// # DKLS23 DKG Ceremony
//
// DKLS23 uses a 4-phase DKG protocol:
//
//	// Create participant state
//	p, err := session.NewDKLS23Participant(threshold, total, myID, sessionID)
//	if err != nil {
//		return err
//	}
//
//	// Phase 1: Generate polynomial
//	phase1, _ := p.DKGPhase1()
//	// Exchange phase1.PolyPoints[j-1] with party j
//
//	// Phase 2: Generate commitments
//	phase2, _ := p.DKGPhase2(receivedPolyPoints)
//	// Broadcast phase2.ProofCommitment
//	// Send phase2.ZeroCommitments[j] to party j
//
//	// Phase 3: Reveal and init multiplication
//	phase3, _ := p.DKGPhase3()
//	// Send phase3.ZeroSeeds[j] and phase3.MulInit[j] to party j
//
//	// Phase 4: Finalize
//	err = p.DKGPhase4(&session.DKLS23DKGPhase4Input{...})
//	// p.Party() is now ready for signing
//
// # DKLS23 Signing
//
// DKLS23 signing also uses a 4-phase protocol:
//
//	// Create signing session
//	sess, _ := session.NewDKLS23SigningSession(party, msgHash, signID, counterparties)
//
//	// Phase 1-4: Exchange messages and finalize
//	p1, _ := sess.Phase1()
//	p2, _ := sess.Phase2(receivedPhase1)
//	p3, _ := sess.Phase3(receivedPhase2)
//	sig, _ := sess.Phase4(allBroadcasts, true)
//
// For local testing, use [DKLS23QuickSign] which handles all phases internally.
//
// # Transport Agnostic
//
// This package does not handle network communication. You are responsible
// for distributing messages between participants using your preferred
// transport (TCP, HTTP, libp2p, etc.). The package only manages protocol
// state and message generation.
package session
