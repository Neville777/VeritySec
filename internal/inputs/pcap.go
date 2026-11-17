package inputs

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
)

// MaxPcapPackets is the hard cap on packets walked; beyond it the result is Partial and Capped.
const MaxPcapPackets = 100000

const topN = 20

// PcapCount is one entry of a top list. Key is an IP address or a port number.
type PcapCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// PcapInfo is what the walk learned. Only Ethernet, IPv4, IPv6, TCP, UDP and DNS question headers
// are decoded; payloads are never kept.
type PcapInfo struct {
	Format      string `json:"format"` // pcap | pcapng
	PacketCount int    `json:"packet_count"`
	LinkType    int    `json:"link_type"` // -1 when unknown
	Truncated   bool   `json:"truncated,omitempty"`

	// Partial is set when something was skipped on purpose: an unsupported pcapng block, a link
	// type other than Ethernet, or the packet cap. It is not an error.
	Partial bool `json:"partial,omitempty"`
	Capped  bool `json:"capped,omitempty"`

	ProtocolCounts map[string]int `json:"protocol_counts,omitempty"`
	TopSrcIPs      []PcapCount    `json:"top_src_ips,omitempty"`
	TopDstIPs      []PcapCount    `json:"top_dst_ips,omitempty"`
	TopDstPorts    []PcapCount    `json:"top_dst_ports,omitempty"`
}

// tally accumulates counters while packets are decoded.
type tally struct {
	protos map[string]int
	src    map[netip.Addr]int
	dst    map[netip.Addr]int
	ports  map[uint16]int
}

func newTally() *tally {
	return &tally{protos: map[string]int{}, src: map[netip.Addr]int{}, dst: map[netip.Addr]int{}, ports: map[uint16]int{}}
}

func (t *tally) finish(info *PcapInfo) {
	info.ProtocolCounts = t.protos
	info.TopSrcIPs = topAddrs(t.src)
	info.TopDstIPs = topAddrs(t.dst)
	info.TopDstPorts = topPorts(t.ports)
}

func rank(items []PcapCount) []PcapCount {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if len(items) > topN {
		items = items[:topN]
	}
	return items
}

func topAddrs(m map[netip.Addr]int) []PcapCount {
	items := make([]PcapCount, 0, len(m))
	for k, v := range m {
		items = append(items, PcapCount{Key: k.String(), Count: v})
	}
	return rank(items)
}

func topPorts(m map[uint16]int) []PcapCount {
	items := make([]PcapCount, 0, len(m))
	for k, v := range m {
		items = append(items, PcapCount{Key: itoa(int(k)), Count: v})
	}
	return rank(items)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// decode reads the headers of one packet. Every access is bounds checked; malformed or short
// packets simply stop the decode at the layer that failed.
func (t *tally) decode(linkType int, p []byte) {
	if linkType != 1 || len(p) < 14 {
		return
	}
	t.protos["ethernet"]++
	et := binary.BigEndian.Uint16(p[12:14])
	p = p[14:]
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8); i++ { // VLAN tags
		if len(p) < 4 {
			return
		}
		et = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}
	var proto byte
	switch et {
	case 0x0800:
		if len(p) < 20 || p[0]>>4 != 4 {
			return
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return
		}
		t.protos["ipv4"]++
		t.src[netip.AddrFrom4([4]byte(p[12:16]))]++
		t.dst[netip.AddrFrom4([4]byte(p[16:20]))]++
		proto = p[9]
		frag := binary.BigEndian.Uint16(p[6:8]) & 0x1fff
		p = p[ihl:]
		if frag != 0 {
			return
		}
	case 0x86dd:
		if len(p) < 40 || p[0]>>4 != 6 {
			return
		}
		t.protos["ipv6"]++
		t.src[netip.AddrFrom16([16]byte(p[8:24]))]++
		t.dst[netip.AddrFrom16([16]byte(p[24:40]))]++
		proto = p[6] // extension headers are not walked
		p = p[40:]
	default:
		return
	}
	switch proto {
	case 6:
		if len(p) < 20 {
			return
		}
		t.protos["tcp"]++
		t.ports[binary.BigEndian.Uint16(p[2:4])]++
	case 17:
		if len(p) < 8 {
			return
		}
		t.protos["udp"]++
		sp, dp := binary.BigEndian.Uint16(p[0:2]), binary.BigEndian.Uint16(p[2:4])
		t.ports[dp]++
		if sp == 53 || dp == 53 {
			if dnsQuestionOK(p[8:]) {
				t.protos["dns"]++
			}
		}
	case 1, 58:
		t.protos["icmp"]++
	}
}

// dnsQuestionOK validates the DNS header and the first question (name labels, type, class).
// Nothing is kept.
func dnsQuestionOK(d []byte) bool {
	if len(d) < 12 || binary.BigEndian.Uint16(d[4:6]) == 0 {
		return false
	}
	i := 12
	for {
		if i >= len(d) {
			return false
		}
		l := int(d[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 { // compression pointers do not appear in a first question
			return false
		}
		i += 1 + l
	}
	return i+4 <= len(d)
}

var ErrNotPcap = errors.New("inputs: not a pcap/pcapng file")

// ParsePcap reads the file header and walks record headers only to count packets. Content over
// MaxContentBytes is refused.
func ParsePcap(b []byte) (*PcapInfo, error) {
	if len(b) > MaxContentBytes {
		return nil, ErrTooLarge
	}
	if len(b) >= 4 && b[0] == 0x0a && b[1] == 0x0d && b[2] == 0x0d && b[3] == 0x0a {
		return parsePcapng(b)
	}
	if len(b) < 24 {
		return nil, ErrNotPcap
	}
	var bo binary.ByteOrder
	switch {
	case b[0] == 0xa1 && b[1] == 0xb2 && (b[2] == 0xc3 && b[3] == 0xd4 || b[2] == 0x3c && b[3] == 0x4d):
		bo = binary.BigEndian
	case b[3] == 0xa1 && b[2] == 0xb2 && (b[1] == 0xc3 && b[0] == 0xd4 || b[1] == 0x3c && b[0] == 0x4d):
		bo = binary.LittleEndian
	default:
		return nil, ErrNotPcap
	}
	info := &PcapInfo{Format: "pcap", LinkType: int(bo.Uint32(b[20:24]) & 0x0fffffff)}
	t := newTally()
	defer t.finish(info)
	if info.LinkType != 1 {
		info.Partial = true // headers are only decoded for Ethernet
	}
	off := 24
	for off+16 <= len(b) {
		incl := int(bo.Uint32(b[off+8 : off+12]))
		next := off + 16 + incl
		if incl < 0 || next > len(b) {
			info.Truncated = true
			break
		}
		if info.PacketCount >= MaxPcapPackets {
			info.Capped, info.Partial = true, true
			return info, nil
		}
		info.PacketCount++
		t.decode(info.LinkType, b[off+16:next])
		off = next
	}
	if off < len(b) && off+16 > len(b) {
		info.Truncated = true
	}
	return info, nil
}

func parsePcapng(b []byte) (*PcapInfo, error) {
	if len(b) < 12 {
		return nil, ErrNotPcap
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(b[8:12]) {
	case 0x1a2b3c4d:
		bo = binary.LittleEndian
	case 0x4d3c2b1a:
		bo = binary.BigEndian
	default:
		return nil, ErrNotPcap
	}
	info := &PcapInfo{Format: "pcapng", LinkType: -1}
	t := newTally()
	defer t.finish(info)
	var ifaces []int
	ifLink := func(i uint32) int {
		if int(i) < len(ifaces) {
			return ifaces[i]
		}
		return -1
	}
	off := 0
	for off+12 <= len(b) {
		typ := bo.Uint32(b[off : off+4])
		l := int(bo.Uint32(b[off+4 : off+8]))
		if l < 12 || l%4 != 0 || off+l > len(b) {
			info.Truncated = true
			break
		}
		switch typ {
		case 0x0a0d0d0a, 4, 5: // section header, name resolution, interface statistics: no packets
		case 1: // interface description: link type is first
			lt := -1
			if l >= 16 {
				lt = int(bo.Uint16(b[off+8 : off+10]))
			}
			ifaces = append(ifaces, lt)
			if info.LinkType < 0 {
				info.LinkType = lt
			}
			if lt != 1 {
				info.Partial = true
			}
		case 2, 3, 6: // packet block, simple packet block, enhanced packet block
			if info.PacketCount >= MaxPcapPackets {
				info.Capped, info.Partial = true, true
				return info, nil
			}
			info.PacketCount++
			blk := b[off : off+l-4]
			var iface uint32
			var data []byte
			switch {
			case typ == 3 && len(blk) >= 12:
				data = blk[12:]
				if ol := int(bo.Uint32(blk[8:12])); ol >= 0 && ol < len(data) {
					data = data[:ol]
				}
			case typ == 6 && len(blk) >= 28:
				iface = bo.Uint32(blk[8:12])
				data = blk[28:]
				if cl := int(bo.Uint32(blk[20:24])); cl >= 0 && cl < len(data) {
					data = data[:cl]
				}
			case typ == 2 && len(blk) >= 28:
				iface = uint32(bo.Uint16(blk[8:10]))
				data = blk[28:]
				if cl := int(bo.Uint32(blk[20:24])); cl >= 0 && cl < len(data) {
					data = data[:cl]
				}
			}
			t.decode(ifLink(iface), data)
		default:
			info.Partial = true // unsupported block type: skipped, not an error
		}
		off += l
	}
	if off < len(b) {
		info.Truncated = true
	}
	return info, nil
}
