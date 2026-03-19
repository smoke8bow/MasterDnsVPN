// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"slices"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const streamOutboundInitialRetryDelay = 350 * time.Millisecond
const streamOutboundMaxRetryDelay = 2 * time.Second
const streamOutboundMinRetryDelay = 120 * time.Millisecond

type streamOutboundStore struct {
	mu         sync.Mutex
	sessions   map[uint8]*streamOutboundSession
	window     int
	queueLimit int
}

type outboundPendingPacket struct {
	Packet     VpnProto.Packet
	CreatedAt  time.Time
	LastSentAt time.Time
	RetryAt    time.Time
	RetryDelay time.Duration
	RetryCount int
}

type streamOutboundSession struct {
	scheduler       *arq.Scheduler
	pending         []outboundPendingPacket
	retryBase       time.Duration
	srtt            time.Duration
	rttVar          time.Duration
	maxPackedBlocks int
}

func newStreamOutboundStore(windowSize int, queueLimit int) *streamOutboundStore {
	if windowSize < 1 {
		windowSize = 1
	}
	if windowSize > 32 {
		windowSize = 32
	}
	if queueLimit < 1 {
		queueLimit = 256
	}
	if queueLimit > 8192 {
		queueLimit = 8192
	}
	return &streamOutboundStore{
		sessions:   make(map[uint8]*streamOutboundSession, 32),
		window:     windowSize,
		queueLimit: queueLimit,
	}
}

func (s *streamOutboundStore) ConfigureSession(sessionID uint8, maxPackedBlocks int) {
	if s == nil || sessionID == 0 {
		return
	}
	s.mu.Lock()
	session := s.ensureSessionLocked(sessionID)
	maxPackedBlocks = max(1, maxPackedBlocks)
	if session.maxPackedBlocks != maxPackedBlocks {
		session.maxPackedBlocks = maxPackedBlocks
		session.scheduler.SetMaxPackedBlocks(maxPackedBlocks)
	}
	s.mu.Unlock()
}

func (s *streamOutboundStore) Enqueue(sessionID uint8, target arq.QueueTarget, packet VpnProto.Packet) bool {
	if s == nil || sessionID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.ensureSessionLocked(sessionID)
	if packet.PacketType == Enums.PACKET_STREAM_DATA && session.scheduler.Pending()+len(session.pending) >= s.queueLimit {
		return false
	}

	queued := arq.QueuedPacket{
		PacketType:      packet.PacketType,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
		Priority:        arq.DefaultPriorityForPacket(packet.PacketType),
	}
	return session.scheduler.Enqueue(target, queued)
}

func (s *streamOutboundStore) Next(sessionID uint8, now time.Time) (VpnProto.Packet, bool) {
	if s == nil || sessionID == 0 {
		return VpnProto.Packet{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return VpnProto.Packet{}, false
	}
	if len(session.pending) < s.window && session.scheduler.Pending() != 0 {
		dequeued, ok := session.scheduler.Dequeue()
		if !ok {
			return VpnProto.Packet{}, false
		}
		packet := vpnPacketFromQueued(dequeued.Packet)
		retryBase := normalizeStreamOutboundRetryBase(session.retryBase)
		if !requiresStreamOutboundAck(packet.PacketType) {
			return packet, true
		}
		session.pending = append(session.pending, outboundPendingPacket{
			Packet:     packet,
			CreatedAt:  now,
			LastSentAt: now,
			RetryAt:    now.Add(retryBase),
			RetryDelay: retryBase,
		})
		return packet, true
	}

	selectedIdx := -1
	for idx := range session.pending {
		if !session.pending[idx].RetryAt.After(now) {
			selectedIdx = idx
			break
		}
	}
	if selectedIdx < 0 {
		return VpnProto.Packet{}, false
	}

	pending := &session.pending[selectedIdx]
	packet := pending.Packet
	delay := pending.RetryDelay
	if delay <= 0 {
		delay = normalizeStreamOutboundRetryBase(session.retryBase)
	}
	pending.LastSentAt = now
	pending.RetryAt = now.Add(delay)
	pending.RetryCount++
	delay *= 2
	if delay > streamOutboundMaxRetryDelay {
		delay = streamOutboundMaxRetryDelay
	}
	pending.RetryDelay = delay
	return packet, true
}

func (s *streamOutboundStore) ExpireStalled(sessionID uint8, now time.Time, maxRetries int, ttl time.Duration) []uint16 {
	if s == nil || sessionID == 0 {
		return nil
	}
	if maxRetries < 1 {
		maxRetries = 24
	}
	if ttl <= 0 {
		ttl = 120 * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || len(session.pending) == 0 {
		return nil
	}

	ttlDeadline := now.Add(-ttl)
	expired := make([]uint16, 0, 2)
	for _, pending := range session.pending {
		if pending.RetryCount < maxRetries && pending.CreatedAt.After(ttlDeadline) {
			continue
		}
		if !slices.Contains(expired, pending.Packet.StreamID) {
			expired = append(expired, pending.Packet.StreamID)
		}
	}
	if len(expired) == 0 {
		return nil
	}

	for _, streamID := range expired {
		prunePendingStreamPackets(session, streamID)
		session.scheduler.HandleStreamReset(streamID)
	}
	if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
		delete(s.sessions, sessionID)
	}
	return expired
}

func (s *streamOutboundStore) Ack(sessionID uint8, packetType uint8, streamID uint16, sequenceNum uint16) bool {
	if s == nil || sessionID == 0 {
		return false
	}
	ackedAt := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || len(session.pending) == 0 {
		return false
	}
	for idx := range session.pending {
		pending := session.pending[idx]
		if !matchesStreamOutboundAck(pending.Packet.PacketType, packetType) {
			continue
		}
		if pending.Packet.StreamID != streamID || pending.Packet.SequenceNum != sequenceNum {
			continue
		}
		updateStreamOutboundRTO(session, pending, ackedAt)
		copy(session.pending[idx:], session.pending[idx+1:])
		lastIdx := len(session.pending) - 1
		session.pending[lastIdx] = outboundPendingPacket{}
		session.pending = session.pending[:lastIdx]
		if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
			delete(s.sessions, sessionID)
		}
		return true
	}
	return false
}

func (s *streamOutboundStore) ClearStream(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return
	}
	prunePendingStreamPackets(session, streamID)
	session.scheduler.HandleStreamReset(streamID)
	if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
		delete(s.sessions, sessionID)
	}
}

func (s *streamOutboundStore) RemoveSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

func (s *streamOutboundStore) ensureSessionLocked(sessionID uint8) *streamOutboundSession {
	session := s.sessions[sessionID]
	if session != nil {
		return session
	}
	session = &streamOutboundSession{
		scheduler:       arq.NewScheduler(1),
		pending:         make([]outboundPendingPacket, 0, s.window),
		retryBase:       streamOutboundInitialRetryDelay,
		maxPackedBlocks: 1,
	}
	s.sessions[sessionID] = session
	return session
}

func vpnPacketFromQueued(packet arq.QueuedPacket) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         packet.PacketType,
		StreamID:           packet.StreamID,
		SequenceNum:        packet.SequenceNum,
		FragmentID:         packet.FragmentID,
		TotalFragments:     packet.TotalFragments,
		CompressionType:    packet.CompressionType,
		HasStreamID:        packet.StreamID != 0,
		HasSequenceNum:     packet.SequenceNum != 0,
		HasFragmentInfo:    packet.TotalFragments != 0 || packet.FragmentID != 0,
		HasCompressionType: packet.CompressionType != 0,
		Payload:            packet.Payload,
	}
}

func prunePendingStreamPackets(session *streamOutboundSession, streamID uint16) {
	if session == nil || len(session.pending) == 0 {
		return
	}
	writeIdx := 0
	for _, pending := range session.pending {
		if pending.Packet.StreamID == streamID {
			continue
		}
		session.pending[writeIdx] = pending
		writeIdx++
	}
	for idx := writeIdx; idx < len(session.pending); idx++ {
		session.pending[idx] = outboundPendingPacket{}
	}
	session.pending = session.pending[:writeIdx]
}

func matchesStreamOutboundAck(pendingType uint8, ackType uint8) bool {
	switch pendingType {
	case Enums.PACKET_STREAM_DATA:
		return ackType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return ackType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return ackType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}

func requiresStreamOutboundAck(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_FIN, Enums.PACKET_STREAM_RST:
		return true
	default:
		return false
	}
}

func normalizeStreamOutboundRetryBase(retryBase time.Duration) time.Duration {
	if retryBase < streamOutboundMinRetryDelay {
		return streamOutboundInitialRetryDelay
	}
	if retryBase > streamOutboundMaxRetryDelay {
		return streamOutboundMaxRetryDelay
	}
	return retryBase
}

func updateStreamOutboundRTO(session *streamOutboundSession, pending outboundPendingPacket, ackedAt time.Time) {
	if session == nil || pending.RetryCount != 0 || pending.LastSentAt.IsZero() {
		return
	}
	sample := ackedAt.Sub(pending.LastSentAt)
	if sample <= 0 {
		return
	}
	if sample < streamOutboundMinRetryDelay {
		sample = streamOutboundMinRetryDelay
	}
	if sample > streamOutboundMaxRetryDelay {
		sample = streamOutboundMaxRetryDelay
	}
	if session.srtt <= 0 {
		session.srtt = sample
		session.rttVar = sample / 2
	} else {
		diff := session.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		session.rttVar = (3*session.rttVar + diff) / 4
		session.srtt = (7*session.srtt + sample) / 8
	}
	rto := session.srtt + 4*session.rttVar
	if rto < streamOutboundMinRetryDelay {
		rto = streamOutboundMinRetryDelay
	}
	if rto > streamOutboundMaxRetryDelay {
		rto = streamOutboundMaxRetryDelay
	}
	session.retryBase = rto
}
