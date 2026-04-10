package udpserver

import (
	"encoding/binary"
	"testing"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestSessionInitPolicyMTULimitsAreAppliedToServerSession(t *testing.T) {
	store := newSessionStore(16, 32)
	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint16(payload[2:4], 999)
	binary.BigEndian.PutUint16(payload[4:6], 9999)
	copy(payload[6:10], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payload, 0, 0, 10, 150, 2048)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused {
		t.Fatal("expected first session init not to be reused")
	}
	if record.UploadMTU != 150 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", record.UploadMTU, 150)
	}
	if record.DownloadMTU != 2048 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", record.DownloadMTU, 2048)
	}
}

func TestHandleSessionInitRequestIncludesServerClientPolicy(t *testing.T) {
	cfg := config.ServerConfig{
		ClientMaxPacketDuplicationCount: 5,
		ClientMaxSetupDuplicationCount:  6,
		ClientMaxUploadMTU:              150,
		ClientMaxDownloadMTU:            4096,
		ClientMaxRxTxWorkers:            64,
		ClientMinPingAggressiveInterval: 0.10,
		ClientMaxPacketsPerBatch:        20,
		ClientMaxARQWindowSize:          6000,
		ClientMaxARQDataNackMaxGap:      200,
		ClientMinCompressionMinSize:     120,
		ClientMinARQInitialRTOSeconds:   0.25,
	}

	s := &Server{
		cfg:                     cfg,
		sessions:                newSessionStore(16, 32),
		uploadCompressionMask:   1 << compression.TypeOff,
		downloadCompressionMask: 1 << compression.TypeOff,
	}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	verifyCode := [4]byte{1, 2, 3, 4}
	initPayload := make([]byte, sessionInitDataSize)
	initPayload[0] = mtuProbeModeRaw
	initPayload[1] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	binary.BigEndian.PutUint16(initPayload[2:4], 220)
	binary.BigEndian.PutUint16(initPayload[4:6], 5000)
	copy(initPayload[6:10], verifyCode[:])

	response := s.handleSessionInitRequest(query, domainMatcher.Decision{RequestName: "x.v.example.com"}, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    initPayload,
	})
	if response == nil {
		t.Fatal("expected session accept response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_SESSION_ACCEPT)
	}

	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionAcceptPayload returned error: %v", err)
	}
	if !accept.HasClientPolicySync {
		t.Fatal("expected session accept to include client policy sync block")
	}
	if accept.VerifyCode != verifyCode {
		t.Fatalf("unexpected verify code: got=%v want=%v", accept.VerifyCode, verifyCode)
	}
	if accept.ClientPolicy.MaxPacketDuplicationCount != cfg.ClientMaxPacketDuplicationCount {
		t.Fatalf("unexpected max packet duplication: got=%d want=%d", accept.ClientPolicy.MaxPacketDuplicationCount, cfg.ClientMaxPacketDuplicationCount)
	}
	if accept.ClientPolicy.MaxSetupDuplicationCount != cfg.ClientMaxSetupDuplicationCount {
		t.Fatalf("unexpected max setup duplication: got=%d want=%d", accept.ClientPolicy.MaxSetupDuplicationCount, cfg.ClientMaxSetupDuplicationCount)
	}
	if accept.ClientPolicy.MaxUploadMTU != cfg.ClientMaxUploadMTU {
		t.Fatalf("unexpected max upload mtu: got=%d want=%d", accept.ClientPolicy.MaxUploadMTU, cfg.ClientMaxUploadMTU)
	}
	if accept.ClientPolicy.MaxDownloadMTU != cfg.ClientMaxDownloadMTU {
		t.Fatalf("unexpected max download mtu: got=%d want=%d", accept.ClientPolicy.MaxDownloadMTU, cfg.ClientMaxDownloadMTU)
	}
	if accept.ClientPolicy.MaxRxTxWorkers != cfg.ClientMaxRxTxWorkers {
		t.Fatalf("unexpected max rx/tx workers: got=%d want=%d", accept.ClientPolicy.MaxRxTxWorkers, cfg.ClientMaxRxTxWorkers)
	}
	if accept.ClientPolicy.MinPingAggressiveInterval < 0.095 || accept.ClientPolicy.MinPingAggressiveInterval > 0.105 {
		t.Fatalf("unexpected min ping aggressive interval: got=%f", accept.ClientPolicy.MinPingAggressiveInterval)
	}
	if accept.ClientPolicy.MaxPacketsPerBatch != cfg.ClientMaxPacketsPerBatch {
		t.Fatalf("unexpected max packets per batch: got=%d want=%d", accept.ClientPolicy.MaxPacketsPerBatch, cfg.ClientMaxPacketsPerBatch)
	}
	if accept.ClientPolicy.MaxARQWindowSize != cfg.ClientMaxARQWindowSize {
		t.Fatalf("unexpected max arq window size: got=%d want=%d", accept.ClientPolicy.MaxARQWindowSize, cfg.ClientMaxARQWindowSize)
	}
	if accept.ClientPolicy.MaxARQDataNackMaxGap != cfg.ClientMaxARQDataNackMaxGap {
		t.Fatalf("unexpected max arq data nack gap: got=%d want=%d", accept.ClientPolicy.MaxARQDataNackMaxGap, cfg.ClientMaxARQDataNackMaxGap)
	}
	if accept.ClientPolicy.MinCompressionMinSize != cfg.ClientMinCompressionMinSize {
		t.Fatalf("unexpected min compression size: got=%d want=%d", accept.ClientPolicy.MinCompressionMinSize, cfg.ClientMinCompressionMinSize)
	}
	if accept.ClientPolicy.MinARQInitialRTOSeconds < 0.245 || accept.ClientPolicy.MinARQInitialRTOSeconds > 0.255 {
		t.Fatalf("unexpected min arq initial rto: got=%f", accept.ClientPolicy.MinARQInitialRTOSeconds)
	}
}
