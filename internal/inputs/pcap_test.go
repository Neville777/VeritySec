package inputs

import (
	"encoding/binary"
	"testing"
)

func TestParsePcapTwoPackets(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		h := make([]byte, 24)
		bo.PutUint32(h[0:], 0xa1b2c3d4)
		bo.PutUint16(h[4:], 2)
		bo.PutUint16(h[6:], 4)
		bo.PutUint32(h[16:], 65535)
		bo.PutUint32(h[20:], 1)
		for i := 0; i < 2; i++ {
			rec := make([]byte, 16+3)
			bo.PutUint32(rec[8:], 3)
			bo.PutUint32(rec[12:], 3)
			h = append(h, rec...)
		}
		info, err := ParsePcap(h)
		if err != nil || info.Format != "pcap" || info.PacketCount != 2 || info.LinkType != 1 || info.Truncated {
			t.Fatalf("%v %+v", err, info)
		}
	}
}

func TestParsePcapTruncatedAndBad(t *testing.T) {
	h := make([]byte, 24+16+5)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint32(h[24+8:], 100) // claims 100 bytes, only 5
	info, err := ParsePcap(h)
	if err != nil || info.PacketCount != 0 || !info.Truncated {
		t.Fatalf("%v %+v", err, info)
	}
	if _, err := ParsePcap([]byte("not a pcap at all, definitely")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParsePcap(make([]byte, MaxContentBytes+1)); err != ErrTooLarge {
		t.Fatalf("%v", err)
	}
}

func TestParsePcapng(t *testing.T) {
	le := binary.LittleEndian
	blk := func(typ uint32, body []byte) []byte {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		b := make([]byte, 12+len(body))
		le.PutUint32(b, typ)
		le.PutUint32(b[4:], uint32(len(b)))
		copy(b[8:], body)
		le.PutUint32(b[len(b)-4:], uint32(len(b)))
		return b
	}
	shb := make([]byte, 16)
	le.PutUint32(shb, 0x1a2b3c4d)
	le.PutUint16(shb[4:], 1)
	for i := 8; i < 16; i++ {
		shb[i] = 0xff
	}
	idb := make([]byte, 8)
	le.PutUint16(idb, 1)
	epb := make([]byte, 28)
	var f []byte
	f = append(f, blk(0x0a0d0d0a, shb)...)
	f = append(f, blk(1, idb)...)
	f = append(f, blk(6, epb)...)
	f = append(f, blk(6, epb)...)
	info, err := ParsePcap(f)
	if err != nil || info.Format != "pcapng" || info.PacketCount != 2 || info.LinkType != 1 || info.Truncated {
		t.Fatalf("%v %+v", err, info)
	}
}

func ipv4Frame(proto byte, src, dst [4]byte, l4 []byte) []byte {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = proto
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	return append(append(eth, ip...), l4...)
}

func tcpHdr(sp, dp uint16) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h, sp)
	binary.BigEndian.PutUint16(h[2:], dp)
	return h
}

func dnsUDP() []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u, 40000)
	binary.BigEndian.PutUint16(u[2:], 53)
	d := make([]byte, 12)
	binary.BigEndian.PutUint16(d[4:], 1)
	d = append(d, 3, 'f', 'o', 'o', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return append(u, d...)
}

func buildPcap(frames ...[]byte) []byte {
	le := binary.LittleEndian
	h := make([]byte, 24)
	le.PutUint32(h, 0xa1b2c3d4)
	le.PutUint32(h[20:], 1)
	for _, f := range frames {
		rec := make([]byte, 16)
		le.PutUint32(rec[8:], uint32(len(f)))
		le.PutUint32(rec[12:], uint32(len(f)))
		h = append(append(h, rec...), f...)
	}
	return h
}

func TestParsePcapDecodesHeaders(t *testing.T) {
	a, b, c := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8}
	f := buildPcap(
		ipv4Frame(6, a, b, tcpHdr(1234, 443)),
		ipv4Frame(6, a, b, tcpHdr(1235, 443)),
		ipv4Frame(17, b, c, dnsUDP()),
	)
	info, err := ParsePcap(f)
	if err != nil || info.PacketCount != 3 || info.Truncated || info.Partial || info.LinkType != 1 {
		t.Fatalf("%v %+v", err, info)
	}
	want := map[string]int{"ethernet": 3, "ipv4": 3, "tcp": 2, "udp": 1, "dns": 1}
	for k, v := range want {
		if info.ProtocolCounts[k] != v {
			t.Fatalf("proto %s=%d want %d: %+v", k, info.ProtocolCounts[k], v, info.ProtocolCounts)
		}
	}
	if len(info.TopSrcIPs) != 2 || info.TopSrcIPs[0] != (PcapCount{"10.0.0.1", 2}) || info.TopSrcIPs[1] != (PcapCount{"10.0.0.2", 1}) {
		t.Fatalf("src %+v", info.TopSrcIPs)
	}
	if len(info.TopDstIPs) != 2 || info.TopDstIPs[0] != (PcapCount{"10.0.0.2", 2}) || info.TopDstIPs[1] != (PcapCount{"8.8.8.8", 1}) {
		t.Fatalf("dst %+v", info.TopDstIPs)
	}
	if len(info.TopDstPorts) != 2 || info.TopDstPorts[0] != (PcapCount{"443", 2}) || info.TopDstPorts[1] != (PcapCount{"53", 1}) {
		t.Fatalf("ports %+v", info.TopDstPorts)
	}
}

func TestParsePcapTruncatedRecordNoPanic(t *testing.T) {
	full := ipv4Frame(6, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, tcpHdr(1, 2))
	f := buildPcap(full, full)
	for cut := 25; cut < len(f); cut++ {
		info, err := ParsePcap(f[:cut])
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		if cut < len(f) && cut != 24+16+len(full) && !info.Truncated {
			t.Fatalf("cut %d not truncated: %+v", cut, info)
		}
	}
	// snaplen-truncated packet content (record complete, headers short) must not panic
	info, err := ParsePcap(buildPcap(full[:30]))
	if err != nil || info.PacketCount != 1 {
		t.Fatalf("%v %+v", err, info)
	}
}

func TestParsePcapngUnsupportedBlockPartial(t *testing.T) {
	le := binary.LittleEndian
	blk := func(typ uint32, body []byte) []byte {
		b := make([]byte, 12+len(body))
		le.PutUint32(b, typ)
		le.PutUint32(b[4:], uint32(len(b)))
		copy(b[8:], body)
		le.PutUint32(b[len(b)-4:], uint32(len(b)))
		return b
	}
	shb := make([]byte, 16)
	le.PutUint32(shb, 0x1a2b3c4d)
	idb := make([]byte, 8)
	le.PutUint16(idb, 1)
	var f []byte
	f = append(f, blk(0x0a0d0d0a, shb)...)
	f = append(f, blk(1, idb)...)
	f = append(f, blk(0x00000bad, make([]byte, 8))...)
	info, err := ParsePcap(f)
	if err != nil || !info.Partial || info.Truncated || info.Format != "pcapng" {
		t.Fatalf("%v %+v", err, info)
	}
}
