// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"net"
	"strings"
	"time"

	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

var ErrInvalidDNSUpstream = errors.New("invalid dns upstream")

type dnsFragmentKey struct {
	sessionID   uint8
	sequenceNum uint16
}

type dnsFragmentEntry struct {
	createdAt      time.Time
	totalFragments uint8
	chunks         [256][]byte
	count          uint8
}

func (s *Server) buildDNSQueryResponsePayload(rawQuery []byte, sessionID uint8, sequenceNum uint16) []byte {
	if !DnsParser.LooksLikeDNSRequest(rawQuery) {
		return nil
	}

	parsed, err := DnsParser.ParsePacketLite(rawQuery)
	if err != nil {
		response, responseErr := DnsParser.BuildFormatErrorResponse(rawQuery)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !parsed.HasQuestion {
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !DnsParser.IsSupportedTunnelDNSQuery(parsed.FirstQuestion.Type, parsed.FirstQuestion.Class) {
		response, responseErr := DnsParser.BuildNotImplementedResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	cacheKey := dnscache.BuildKey(parsed.FirstQuestion.Name, parsed.FirstQuestion.Type, parsed.FirstQuestion.Class)
	now := time.Now()
	if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
		if s.log != nil {
			s.log.Debugf(
				"🧠 <green>Tunnel DNS Cache Hit</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		return cached
	}

	inflightEntry, leader := s.dnsResolveInflight.Acquire(cacheKey, now)
	if !leader {
		if s.log != nil {
			s.log.Debugf(
				"🧩 <green>Tunnel DNS Inflight Reused</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		waitTimeout := s.cfg.DNSUpstreamTimeout() * 2
		if waitTimeout <= 0 {
			waitTimeout = 8 * time.Second
		}
		if resolved, ok := s.dnsResolveInflight.Wait(inflightEntry, waitTimeout); ok && len(resolved) != 0 {
			return dnscache.PatchResponseForQuery(resolved, rawQuery)
		}
		if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
			return cached
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	resolved, err := s.resolveDNSUpstream(rawQuery)
	if s.log != nil {
		s.log.Debugf(
			"🔎 <green>Tunnel DNS Upstream Lookup</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
		)
	}
	s.dnsResolveInflight.Resolve(cacheKey, resolved)
	if err != nil || len(resolved) == 0 {
		if s.log != nil {
			s.log.Debugf(
				"⚠️ <yellow>Tunnel DNS Upstream Failed</yellow> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	s.dnsCache.SetReady(
		cacheKey,
		parsed.FirstQuestion.Name,
		parsed.FirstQuestion.Type,
		parsed.FirstQuestion.Class,
		resolved,
		now,
	)
	if s.log != nil {
		s.log.Debugf(
			"🌍 <green>Tunnel DNS Resolved Upstream</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
			len(resolved),
		)
	}
	return resolved
}

func (s *Server) collectDNSQueryFragments(sessionID uint8, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool) {
	if totalFragments <= 1 {
		return payload, true
	}
	if totalFragments == 0 || fragmentID >= totalFragments {
		return nil, false
	}

	s.dnsFragmentMu.Lock()
	defer s.dnsFragmentMu.Unlock()

	s.purgeDNSQueryFragmentsLocked(now)

	key := dnsFragmentKey{sessionID: sessionID, sequenceNum: sequenceNum}
	entry, ok := s.dnsFragments[key]
	if !ok || entry.totalFragments != totalFragments {
		entry = &dnsFragmentEntry{
			createdAt:      now,
			totalFragments: totalFragments,
		}
		s.dnsFragments[key] = entry
	}

	if entry.chunks[fragmentID] == nil {
		entry.count++
	}
	entry.chunks[fragmentID] = append(entry.chunks[fragmentID][:0], payload...)

	if entry.count < totalFragments {
		return nil, false
	}

	totalSize := 0
	for i := uint8(0); i < totalFragments; i++ {
		chunk := entry.chunks[i]
		if chunk == nil {
			return nil, false
		}
		totalSize += len(chunk)
	}

	assembled := make([]byte, 0, totalSize)
	for i := uint8(0); i < totalFragments; i++ {
		assembled = append(assembled, entry.chunks[i]...)
	}
	delete(s.dnsFragments, key)
	return assembled, true
}

func (s *Server) purgeDNSQueryFragments(now time.Time) {
	s.dnsFragmentMu.Lock()
	s.purgeDNSQueryFragmentsLocked(now)
	s.dnsFragmentMu.Unlock()
}

func (s *Server) purgeDNSQueryFragmentsLocked(now time.Time) {
	timeout := s.cfg.DNSFragmentAssemblyTimeout()
	if timeout <= 0 {
		timeout = 16 * time.Second
	}
	for key, entry := range s.dnsFragments {
		if now.Sub(entry.createdAt) >= timeout {
			delete(s.dnsFragments, key)
		}
	}
}

func (s *Server) resolveDNSUpstream(rawQuery []byte) ([]byte, error) {
	if s != nil && s.resolveDNSQueryFn != nil {
		return s.resolveDNSQueryFn(rawQuery)
	}
	if len(rawQuery) == 0 || len(s.dnsUpstreamServers) == 0 {
		return nil, ErrInvalidDNSUpstream
	}

	timeout := s.cfg.DNSUpstreamTimeout()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	for _, upstream := range s.dnsUpstreamServers {
		conn, err := newUDPUpstreamConn(upstream)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, writeErr := conn.Write(rawQuery)
		if writeErr != nil {
			_ = conn.Close()
			continue
		}

		buffer := s.dnsUpstreamBufferPool.Get().([]byte)
		n, readErr := conn.Read(buffer)
		_ = conn.Close()
		if readErr == nil && n > 0 {
			response := append([]byte(nil), buffer[:n]...)
			s.dnsUpstreamBufferPool.Put(buffer)
			return response, nil
		}
		s.dnsUpstreamBufferPool.Put(buffer)
	}

	return nil, ErrInvalidDNSUpstream
}

func newUDPUpstreamConn(endpoint string) (*net.UDPConn, error) {
	host, port, err := splitHostPortDefault53(endpoint)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

func splitHostPortDefault53(value string) (string, string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", "", ErrInvalidDNSUpstream
	}

	if strings.HasPrefix(text, "[") {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	if strings.Count(text, ":") == 0 {
		return text, "53", nil
	}
	if strings.Count(text, ":") == 1 {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	return text, "53", nil
}
