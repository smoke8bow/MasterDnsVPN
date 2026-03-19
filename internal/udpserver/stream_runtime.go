// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"io"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const minStreamReadBuffer = 256

func (s *Server) startStreamUpstreamReadLoop(sessionID uint8, streamID uint16, conn io.ReadCloser, compressionType uint8, mtu int) {
	if s == nil || conn == nil {
		return
	}

	bufferSize := computeStreamReadBufferSize(mtu)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if s.log != nil {
					s.log.Errorf(
						"💥 <red>Upstream Stream Read Panic Recovered</red> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <yellow>%v</yellow>",
						sessionID,
						streamID,
						recovered,
					)
				}
				now := time.Now()
				if rstSeq, ok := s.streams.NextOutboundSequence(sessionID, streamID, now); ok {
					_ = s.streams.MarkReset(sessionID, streamID, rstSeq, now)
					_ = s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
						PacketType:  Enums.PACKET_STREAM_RST,
						StreamID:    streamID,
						SequenceNum: rstSeq,
					})
				}
			}
			_ = conn.Close()
		}()

		buffer := make([]byte, bufferSize)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				now := time.Now()
				sequenceNum, ok := s.streams.NextOutboundSequence(sessionID, streamID, now)
				if !ok {
					return
				}
				if !s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
					PacketType:      Enums.PACKET_STREAM_DATA,
					StreamID:        streamID,
					SequenceNum:     sequenceNum,
					CompressionType: compressionType,
					Payload:         append([]byte(nil), buffer[:n]...),
				}) {
					if s.log != nil {
						s.log.Warnf(
							"🚧 <yellow>Upstream Stream Backpressure</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan>",
							sessionID,
							streamID,
						)
					}
					rstNow := time.Now()
					if rstSeq, ok := s.streams.NextOutboundSequence(sessionID, streamID, rstNow); ok {
						_ = s.streams.MarkReset(sessionID, streamID, rstSeq, rstNow)
						_ = s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
							PacketType:  Enums.PACKET_STREAM_RST,
							StreamID:    streamID,
							SequenceNum: rstSeq,
						})
					}
					return
				}
			}

			if err == nil {
				continue
			}
			if err == io.EOF {
				now := time.Now()
				if sequenceNum, ok := s.streams.NextOutboundSequence(sessionID, streamID, now); ok {
					_, _ = s.streams.MarkLocalFin(sessionID, streamID, sequenceNum, now)
					_ = s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
						PacketType:  Enums.PACKET_STREAM_FIN,
						StreamID:    streamID,
						SequenceNum: sequenceNum,
					})
				}
				return
			}

			if s.log != nil {
				s.log.Debugf(
					"📥 <yellow>Upstream Read Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
					sessionID,
					streamID,
					err,
				)
			}
			now := time.Now()
			if sequenceNum, ok := s.streams.NextOutboundSequence(sessionID, streamID, now); ok {
				_ = s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
					PacketType:  Enums.PACKET_STREAM_RST,
					StreamID:    streamID,
					SequenceNum: sequenceNum,
				})
			}
			return
		}
	}()
}

func computeStreamReadBufferSize(mtu int) int {
	if mtu < minStreamReadBuffer {
		return minStreamReadBuffer
	}
	if mtu > 2048 {
		return 2048
	}
	return mtu
}
