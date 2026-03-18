// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrTunnelDNSDispatchFailed = errors.New("dns tunnel dispatch failed")

func (c *Client) dispatchDNSQuery(request *dnsDispatchRequest) (response []byte, err error) {
	if c == nil || request == nil || len(request.Query) == 0 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if c.sessionID == 0 {
		return nil, ErrSessionInitFailed
	}
	defer func() {
		if err != nil {
			c.dnsInflight.Complete(request.CacheKey)
		}
	}()

	packet, err := c.exchangeMainStreamPacket(Enums.PACKET_DNS_QUERY_REQ, request.Query)
	if err != nil {
		return nil, err
	}
	if packet.PacketType != Enums.PACKET_DNS_QUERY_RES {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(packet.Payload) < 12 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if shouldCacheTunnelDNSResponse(packet.Payload) {
		c.localDNSCache.SetReady(
			request.CacheKey,
			request.Domain,
			request.QType,
			request.QClass,
			packet.Payload,
			c.now(),
		)
	}
	c.dnsInflight.Complete(request.CacheKey)
	return packet.Payload, nil
}

func (c *Client) exchangeMainStreamPacket(packetType uint8, payload []byte) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	timeout := time.Duration(c.cfg.LocalDNSPendingTimeoutSec * float64(time.Second))
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	connections := c.GetUniqueConnections(3)
	if len(connections) == 0 {
		return VpnProto.Packet{}, ErrNoValidConnections
	}

	sequenceNum := c.nextMainSequence()
	lastErr := ErrTunnelDNSDispatchFailed
	for _, connection := range connections {
		packet, err := c.exchangeMainStreamPacketWithConnection(connection, packetType, sequenceNum, payload, timeout)
		if err == nil {
			return packet, nil
		}
		c.SetConnectionValidity(connection.Key, false)
		lastErr = err
	}

	return VpnProto.Packet{}, lastErr
}

func (c *Client) exchangeMainStreamPacketWithConnection(connection Connection, packetType uint8, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	fragments := c.fragmentMainStreamPayload(payload)
	for fragmentID, fragmentPayload := range fragments {
		query, err := c.buildMainStreamQuery(
			connection.Domain,
			packetType,
			sequenceNum,
			uint8(fragmentID),
			uint8(len(fragments)),
			fragmentPayload,
		)
		if err != nil {
			return VpnProto.Packet{}, err
		}

		response, err := c.exchangeDNSOverConnection(connection, query, timeout)
		if err != nil {
			return VpnProto.Packet{}, err
		}
		if fragmentID < len(fragments)-1 {
			continue
		}

		packet, err := DnsParser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
		if err != nil || !c.validateServerPacket(packet) {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		if packet.StreamID != 0 || packet.SequenceNum != sequenceNum {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		return packet, nil
	}

	return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
}

func (c *Client) buildMainStreamQuery(domain string, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte) ([]byte, error) {
	encoded, err := VpnProto.BuildEncodedAuto(VpnProto.BuildOptions{
		SessionID:       c.sessionID,
		PacketType:      packetType,
		SessionCookie:   c.sessionCookie,
		StreamID:        0,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: c.uploadCompression,
		Payload:         payload,
	}, c.codec, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	name, err := DnsParser.BuildTunnelQuestionName(domain, encoded)
	if err != nil {
		return nil, err
	}
	return DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}

func (c *Client) fragmentMainStreamPayload(payload []byte) [][]byte {
	if len(payload) == 0 {
		return [][]byte{{}}
	}

	limit := c.syncedUploadMTU
	if limit <= 0 {
		limit = EDnsSafeUDPSize
	}
	if limit < 1 {
		limit = 1
	}
	if len(payload) <= limit {
		return [][]byte{payload}
	}

	total := (len(payload) + limit - 1) / limit
	if total > 255 {
		total = 255
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(payload) && len(fragments) < total; start += limit {
		end := start + limit
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[start:end])
	}
	return fragments
}

func (c *Client) exchangeDNSOverConnection(connection Connection, packet []byte, timeout time.Duration) ([]byte, error) {
	if c != nil && c.exchangeQueryFn != nil {
		return c.exchangeQueryFn(connection, packet, timeout)
	}

	transport, err := newUDPQueryTransport(connection.ResolverLabel)
	if err != nil {
		return nil, err
	}
	defer transport.conn.Close()
	return exchangeUDPQuery(transport, packet, timeout)
}

func (c *Client) nextMainSequence() uint16 {
	if c == nil {
		return 1
	}
	c.mainSequence++
	if c.mainSequence == 0 {
		c.mainSequence = 1
	}
	return c.mainSequence
}

func shouldCacheTunnelDNSResponse(response []byte) bool {
	if len(response) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(response[2:4])&0x000F != Enums.DNSR_CODE_SERVER_FAILURE
}

type udpQueryTransport struct {
	conn   *net.UDPConn
	buffer []byte
}

func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &udpQueryTransport{
		conn:   conn,
		buffer: make([]byte, EDnsSafeUDPSize),
	}, nil
}

func exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if err := transport.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := transport.conn.Write(packet); err != nil {
		return nil, err
	}

	n, err := transport.conn.Read(transport.buffer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), transport.buffer[:n]...), nil
}
