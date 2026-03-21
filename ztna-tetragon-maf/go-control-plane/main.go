package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// --- 構造体定義 ---

type FlowKey struct {
	Ip       uint32
	Port     uint16
	Protocol uint8
	Pad      uint8
}

type IpStats struct {
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	DroppedPackets uint64 `json:"dropped_packets"`
	SynPackets     uint64 `json:"syn_packets"`
	RstPackets     uint64 `json:"rst_packets"`
	AckPackets     uint64 `json:"ack_packets"`
	LastTs         uint64 `json:"last_ts"`
	FlowStartNs    uint64 `json:"flow_start_ns"`
	UserId         uint32 `json:"user_id"`
	PolicyStatus   uint32 `json:"policy_status"`
	L7ProtoLabel   uint32 `json:"l7_proto_label"`
	PktMin         uint32 `json:"pkt_min"`
	PktMax         uint32 `json:"pkt_max"`
	Pad            uint32 `json:"-"`
}

type QosConfig struct {
	LimitBytesPerSec uint64
	Tokens           uint64
	LastUpdated      uint64
}

type AuthInfo struct {
	Expiry   uint64 `json:"expiry"`
	Priority uint32 `json:"priority"`
	UserId   uint32 `json:"user_id"`
}

type RedirectConfig struct {
	Ifindex uint32
}

type ResponseEntry struct {
	Ip       string  `json:"ip"`
	Port     uint16  `json:"port"`
	Protocol string  `json:"protocol"`
	Stats    IpStats `json:"stats"`
}

type AuthLog struct {
	Timestamp time.Time `json:"timestamp"`
	RemoteIP  string    `json:"remote_ip"`
	Magic     string    `json:"magic"`
	Action    string    `json:"action"`
}

var (
	authHistory  []AuthLog
	logMutex     sync.Mutex
	currentIface string
	currentMode  string

	// チケット発行ロック（/auth/lock で true にすると発行禁止）
	ticketLocked   bool
	ticketLockOnce sync.Once // ロック解除は再起動のみ
	ticketMu       sync.Mutex

	// revoke済みIPのブラックリスト（再認証を拒否する）
	revokeBlacklist   = make(map[uint32]time.Time) // ip -> revoke時刻
	blacklistMu       sync.RWMutex
	blacklistDuration = 10 * time.Minute // ブラックリスト保持時間
)

func main() {
	ifaceFlag := flag.String("iface", "", "Network interface name (required)")
	xdpModeFlag := flag.String("xdp-mode", "auto", "XDP mode: native, generic, or auto (default: auto)")
	flag.Parse()

	if *ifaceFlag == "" {
		log.Fatal("Usage: sudo ./sase-agent -iface <iface> [-xdp-mode native|generic|auto]")
	}

	xdpMode := validateXDPMode(*xdpModeFlag)
	ifaceName := *ifaceFlag
	currentIface = ifaceName
	currentMode = xdpMode

	log.Printf("✅ Interface: %s, XDP Mode: %s", ifaceName, xdpMode)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed to remove memlock limit:", err)
	}

	// eBPF オブジェクトファイルの存在確認
	ebpfPath := "main.elf"
	if _, err := os.Stat(ebpfPath); err != nil {
		ebpfPath = "main.o"
		if _, err := os.Stat(ebpfPath); err != nil {
			log.Fatalf("eBPF object file not found (tried main.elf and main.o): %v", err)
		}
	}

	log.Printf("✅ Using eBPF object: %s", ebpfPath)

	spec, err := ebpf.LoadCollectionSpec(ebpfPath)
	if err != nil {
		log.Fatalf("failed to load collection spec from %s: %v", ebpfPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create new collection: %v", err)
	}
	defer coll.Close()

	if coll.Programs["xdp_filter"] == nil {
		log.Fatal("xdp_filter program not found in eBPF object")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to find interface %s: %v", ifaceName, err)
	}

	// XDP アタッチ
	l := attachXDPProgram(coll.Programs["xdp_filter"], iface.Index, xdpMode)
	defer l.Close()

	// マップへの参照取得
	statsMap := coll.Maps["STATS_MAP"]
	authIps := coll.Maps["AUTH_IPS"]
	dropList := coll.Maps["DROP_LIST"]
	qosMap := coll.Maps["QOS_MAP"]
	configMap := coll.Maps["CONFIG_MAP"]
	redirectConfig := coll.Maps["REDIRECT_CONFIG"]

	if statsMap == nil || authIps == nil || dropList == nil || qosMap == nil || configMap == nil || redirectConfig == nil {
		log.Fatal("Failed to load one or more eBPF maps")
	}

	log.Printf("✅ All eBPF maps loaded successfully")

	// CONFIG_MAP[key=1] に認証有効期限（300秒）を書き込む
	// main.rs の DEFAULT_AUTH_DURATION = 300 * 1_000_000_000 ns と同値
	// これにより /config エンドポイントが "auth_duration_ns: 300000000000" を返すようになる
	durationKey := uint32(1)
	durationVal := uint64(300 * 1_000_000_000)
	if err := configMap.Put(&durationKey, &durationVal); err != nil {
		log.Printf("⚠️  Failed to set CONFIG_MAP[1] (auth_duration): %v", err)
	} else {
		log.Printf("✅ AUTH duration set: 300s")
	}

	// xdp0 の ifindex を取得して REDIRECT_CONFIG に入れる
	xdp0, err := net.InterfaceByName("xdp0")
	if err != nil {
		log.Printf("⚠️  xdp0 interface not found: %v (redirect will fallback to XDP_PASS)", err)
	} else {
		redirectCfg := RedirectConfig{
			Ifindex: uint32(xdp0.Index),
		}
		key := uint32(0)
		if err := redirectConfig.Put(&key, &redirectCfg); err != nil {
			log.Printf("⚠️  Failed to set REDIRECT_CONFIG: %v", err)
		} else {
			log.Printf("✅ Redirect target set to xdp0 (ifindex=%d)", xdp0.Index)
		}
	}

	// 自律防御 ＋ 自動復旧ループ
	// [不具合修正] 復旧チェックをelse外に移動し、SYNスパイク継続中でも復旧できるようにした
	go func(sMap *ebpf.Map, aMap *ebpf.Map) {
		prevSynCounts := make(map[FlowKey]uint64)
		alertCounts := make(map[FlowKey]int)
		isolatedAt := make(map[uint32]time.Time)

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var key FlowKey
			var stats IpStats
			iter := sMap.Iterate()

			for iter.Next(&key, &stats) {
				currentSyn := stats.SynPackets
				prevSyn := prevSynCounts[key]

				delta := uint64(0)
				if currentSyn >= prevSyn {
					delta = currentSyn - prevSyn
				} else {
					delta = currentSyn
				}

				if delta > 0 {
					log.Printf("[Debug] IP: %v, Port: %d, Delta: %d", intToIP(key.Ip), key.Port, delta)
				}

				if delta > 300 {
					alertCounts[key]++
					if alertCounts[key] >= 2 {
						var auth AuthInfo
						if err := aMap.Lookup(key.Ip, &auth); err == nil && auth.Priority > 1 {
							auth.Priority = 1
							aMap.Put(key.Ip, &auth)
							isolatedAt[key.Ip] = time.Now()
							log.Printf("[Defense] 🚨 Isolated %s: Persistent SYN Spike on port %d (Delta: %d)", intToIP(key.Ip), key.Port, delta)
						}
					}
				} else {
					alertCounts[key] = 0
				}

				// 復旧チェック: deltaの大小に関わらず常に評価する
				if isoTime, ok := isolatedAt[key.Ip]; ok && time.Since(isoTime) > 1*time.Minute {
					var auth AuthInfo
					if err := aMap.Lookup(key.Ip, &auth); err == nil && auth.Priority == 1 {
						auth.Priority = 2
						aMap.Put(key.Ip, &auth)
						delete(isolatedAt, key.Ip)
						log.Printf("[Recovery] ✅ Restored %s: Traffic stabilized.", intToIP(key.Ip))
					}
				}

				prevSynCounts[key] = currentSyn
			}

			if err := iter.Err(); err != nil {
				log.Printf("⚠️ Iterator error: %v", err)
			}
		}
	}(statsMap, authIps)

	// --- APIハンドラ登録（main_final.goのパスに統一）---
	http.HandleFunc("/info", handleInfo)
	http.HandleFunc("/stats", handleGetStats(statsMap))
	http.HandleFunc("/top", handleTopStats(statsMap))
	http.HandleFunc("/config", handleConfig(configMap))
	http.HandleFunc("/auth/ticket", handleIssueTicket(configMap))
	http.HandleFunc("/auth/revoke", handleClearIdentity(authIps))
	http.HandleFunc("/auth/lock", handleLockTicket)
	http.HandleFunc("/auth/blacklist", handleGetBlacklist)
	http.HandleFunc("/auth/priority", handleSetPriority(authIps, qosMap))
	http.HandleFunc("/auth/logs", handleGetAuthLogs)
	http.HandleFunc("/auth/identities", handleGetIdentities(authIps))
	http.HandleFunc("/drop/list", handleList(dropList))
	http.HandleFunc("/drop/block", handleBlock(dropList))
	http.HandleFunc("/drop/unblock", handleUnblock(dropList))
	http.HandleFunc("/qos/set", handleSetQoS(qosMap))

	log.Printf("🚀 AIBN Agent running on %s", ifaceName)
	log.Printf("📊 API Endpoint: http://localhost:8080")
	log.Printf("📋 Available endpoints:")
	log.Printf("   GET /info - Get agent info (interface, xdp_mode, version)")
	log.Printf("   GET /auth/identities - List authenticated sessions")
	log.Printf("   GET /stats - Get all flow statistics")
	log.Printf("   GET /top - Get top 10 flows by packet count")
	log.Printf("   GET /auth/priority?ip=X.X.X.X&level=1|2|3 - Set priority")
	log.Printf("   GET /auth/revoke?ip=X.X.X.X - Revoke authentication")
	log.Printf("   GET /qos/set?ip=X.X.X.X&limit=BYTES_PER_SEC - Set QoS limit")
	log.Printf("   GET /drop/block?ip=X.X.X.X&proto=tcp|udp|icmp&port=PORT - Block flow")
	log.Printf("   GET /drop/unblock?ip=X.X.X.X&proto=tcp|udp|icmp&port=PORT - Unblock flow")
	log.Printf("   GET /drop/list - List blocked flows")
	log.Printf("   GET /auth/ticket?magic=0xHEX - Issue authentication ticket")
	log.Printf("   GET /auth/lock - Lock ticket issuance (permanent until restart)")
	log.Printf("   GET /auth/blacklist - List blacklisted IPs")
	log.Printf("   GET /config - Get kernel state")
	log.Printf("   GET /auth/logs - Get authentication logs")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// validateXDPMode はXDPモードの入力値を検証・正規化する
func validateXDPMode(xdpMode string) string {
	xdpMode = strings.ToLower(strings.TrimSpace(xdpMode))
	switch xdpMode {
	case "native", "generic", "auto":
		return xdpMode
	case "":
		return "auto"
	default:
		log.Fatalf("Invalid -xdp-mode: %q. Use native, generic, or auto.", xdpMode)
		return ""
	}
}

// attachXDPProgram はXDPプログラムを指定モードでアタッチする
func attachXDPProgram(prog *ebpf.Program, ifindex int, mode string) link.Link {
	var l link.Link
	var err error

	switch mode {
	case "native":
		log.Printf("📌 Attaching XDP in Native/Driver mode...")
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     link.XDPDriverMode,
		})
		if err != nil {
			log.Fatalf("❌ Failed to attach XDP in Native mode: %v", err)
		}
		log.Printf("✅ XDP attached (Native/Driver mode)")

	case "generic":
		log.Printf("📌 Attaching XDP in Generic mode...")
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("❌ Failed to attach XDP in Generic mode: %v", err)
		}
		log.Printf("✅ XDP attached (Generic mode)")

	case "auto":
		log.Printf("📌 Attaching XDP (Native mode, fallback to Generic)...")
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     link.XDPDriverMode,
		})
		if err != nil {
			log.Printf("⚠️  Native mode failed, falling back to Generic: %v", err)
			l, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: ifindex,
				Flags:     link.XDPGenericMode,
			})
			if err != nil {
				log.Fatalf("❌ Failed to attach XDP (both native and generic): %v", err)
			}
			log.Printf("✅ XDP attached (Generic mode, fallback)")
		} else {
			log.Printf("✅ XDP attached (Native/Driver mode)")
		}
	}

	return l
}

// --- ハンドラ群 ---

func handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"interface": currentIface,
		"xdp_mode":  currentMode,
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"note":      "VPP determines zero-copy or copy mode automatically via af_xdp based on NIC capabilities",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleGetIdentities(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			key     uint32
			val     AuthInfo
			results = make(map[string]AuthInfo)
		)

		iter := m.Iterate()
		for iter.Next(&key, &val) {
			ipStr := intToIP(key).String()
			results[ipStr] = val
		}

		if err := iter.Err(); err != nil {
			log.Printf("⚠️ Iteration Error: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}

func handleSetPriority(authMap *ebpf.Map, qosMap *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ipStr, prioStr := q.Get("ip"), q.Get("level")
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", 400)
			return
		}

		var level uint32
		fmt.Sscanf(prioStr, "%d", &level)

		if level < 1 || level > 3 {
			http.Error(w, "Invalid level: Use 1(Bulk), 2(Normal), or 3(VIP)", 400)
			return
		}

		key := binary.BigEndian.Uint32(ip)

		var auth AuthInfo
		if err := authMap.Lookup(&key, &auth); err != nil {
			http.Error(w, "Identity not found.", 404)
			return
		}
		auth.Priority = level
		authMap.Put(&key, &auth)

		var qos QosConfig
		if err := qosMap.Lookup(&key, &qos); err == nil {
			log.Printf("[Slicing] IP %s is now Priority %d (QoS Base Limit: %d B/s)", ipStr, level, qos.LimitBytesPerSec)
		}

		log.Printf("[EVENT] TYPE=PRIORITY_CHANGE IP=%s LEVEL=%d", ipStr, level)

		fmt.Fprintf(w, "Successfully set %s to Priority %d\n", ipStr, level)
	}
}

func handleIssueTicket(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ロック中は発行拒否
		ticketMu.Lock()
		locked := ticketLocked
		ticketMu.Unlock()
		if locked {
			http.Error(w, "Ticket issuance is locked. Restart agent to unlock.", 403)
			log.Printf("🔒 Ticket issuance rejected (locked): remote=%s", r.RemoteAddr)
			return
		}

		valStr := r.URL.Query().Get("magic")
		var magic uint64
		if _, err := fmt.Sscanf(valStr, "0x%x", &magic); err != nil {
			if _, err2 := fmt.Sscanf(valStr, "%x", &magic); err2 != nil {
				http.Error(w, "Invalid hex format", 400)
				return
			}
		}

		// magic=0 は禁止（「0チケット発行」による偽無効化を防ぐ）
		if magic == 0 {
			http.Error(w, "magic=0 is reserved and cannot be issued as a ticket", 400)
			log.Printf("⚠️  Rejected magic=0 ticket request: remote=%s", r.RemoteAddr)
			return
		}

		// ブラックリスト確認（発行元IPが revoke済みなら拒否）
		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		remoteIP := net.ParseIP(remoteHost).To4()
		if remoteIP != nil {
			remoteKey := binary.BigEndian.Uint32(remoteIP)
			blacklistMu.RLock()
			revokedAt, inBL := revokeBlacklist[remoteKey]
			blacklistMu.RUnlock()
			if inBL && time.Since(revokedAt) < blacklistDuration {
				http.Error(w, "Source IP is blacklisted", 403)
				log.Printf("🚫 Ticket rejected (blacklisted IP): remote=%s", r.RemoteAddr)
				return
			}
		}

		key := uint32(0)
		magicBE := magic
		m.Put(&key, &magicBE)

		logMutex.Lock()
		authHistory = append(authHistory, AuthLog{
			Timestamp: time.Now(),
			RemoteIP:  r.RemoteAddr,
			Magic:     valStr,
			Action:    "TICKET_ISSUED",
		})
		logMutex.Unlock()

		log.Printf("🎫 Ticket Issued: %s", valStr)
		fmt.Fprintf(w, "Ticket %s active.\n", valStr)
	}
}

// handleLockTicket はチケット発行を永続的に禁止する（再起動まで解除不可）
func handleLockTicket(w http.ResponseWriter, r *http.Request) {
	ticketMu.Lock()
	ticketLocked = true
	ticketMu.Unlock()
	log.Printf("🔒 Ticket issuance LOCKED by %s", r.RemoteAddr)
	fmt.Fprintf(w, "Ticket issuance locked. No new tickets will be accepted until agent restart.\n")
}

// handleGetBlacklist はブラックリスト中のIPと残り時間を返す
func handleGetBlacklist(w http.ResponseWriter, r *http.Request) {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()

	type entry struct {
		IP        string `json:"ip"`
		RevokedAt string `json:"revoked_at"`
		ExpiresIn string `json:"expires_in"`
	}
	now := time.Now()
	var entries []entry
	for ipInt, revokedAt := range revokeBlacklist {
		remaining := blacklistDuration - now.Sub(revokedAt)
		if remaining <= 0 {
			continue
		}
		entries = append(entries, entry{
			IP:        intToIP(ipInt).String(),
			RevokedAt: revokedAt.Format(time.RFC3339),
			ExpiresIn: remaining.Round(time.Second).String(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func collectStats(m *ebpf.Map) []ResponseEntry {
	var (
		key     FlowKey
		val     IpStats
		entries []ResponseEntry
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		entries = append(entries, ResponseEntry{
			Ip:       intToIP(key.Ip).String(),
			Port:     key.Port,
			Protocol: getProtoName(key.Protocol),
			Stats:    val,
		})
	}
	return entries
}

func handleGetAuthLogs(w http.ResponseWriter, r *http.Request) {
	logMutex.Lock()
	defer logMutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authHistory)
}

func handleConfig(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m0, m1 uint64
		k0, k1 := uint32(0), uint32(1)
		m.Lookup(&k0, &m0)
		m.Lookup(&k1, &m1)
		results := map[string]interface{}{
			"current_magic_ticket": fmt.Sprintf("0x%x", m0),
			"auth_duration_ns":     m1,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}

func handleClearIdentity(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ipStr := r.URL.Query().Get("ip")
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", 400)
			return
		}
		key := binary.BigEndian.Uint32(ip)

		// AUTH_IPS から削除
		m.Delete(&key)

		// ブラックリストに追加（blacklistDuration の間、再認証を拒否）
		blacklistMu.Lock()
		revokeBlacklist[key] = time.Now()
		blacklistMu.Unlock()

		logMutex.Lock()
		authHistory = append(authHistory, AuthLog{
			Timestamp: time.Now(),
			RemoteIP:  r.RemoteAddr,
			Magic:     "-",
			Action:    "REVOKED_AND_BLACKLISTED:" + ipStr,
		})
		logMutex.Unlock()

		log.Printf("🚫 Revoked and blacklisted: %s (duration: %s)", ipStr, blacklistDuration)
		fmt.Fprintf(w, "Revoked and blacklisted: %s (for %s)\n", ipStr, blacklistDuration)
	}
}

func handleGetStats(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := collectStats(m)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Ip < entries[j].Ip })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

func handleTopStats(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := collectStats(m)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Stats.Packets > entries[j].Stats.Packets })
		limit := 10
		if len(entries) < limit {
			limit = len(entries)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries[:limit])
	}
}

func handleList(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var key FlowKey
		var val uint32
		entries := make(map[string]string)
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			ipStr := intToIP(key.Ip).String()
			entryKey := fmt.Sprintf("%s:%d [%s]", ipStr, key.Port, getProtoName(key.Protocol))
			entries[entryKey] = "BLOCKED"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

func handleBlock(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ipStr, protoStr, port, err := parseFlowParams(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		val := uint32(1)
		m.Put(&key, &val)
		fmt.Fprintf(w, "Blocked: %s %s:%d\n", protoStr, ipStr, port)
	}
}

func handleUnblock(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, _, _, _, _ := parseFlowParams(r)
		m.Delete(&key)
		fmt.Fprintf(w, "Unblocked\n")
	}
}

func handleSetQoS(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ipStr := q.Get("ip")
		var limit uint64
		fmt.Sscanf(q.Get("limit"), "%d", &limit)
		ip := net.ParseIP(ipStr).To4()
		if ip != nil {
			key := binary.BigEndian.Uint32(ip)
			config := QosConfig{LimitBytesPerSec: limit, Tokens: limit, LastUpdated: 0}
			m.Put(&key, &config)
			fmt.Fprintf(w, "QoS Applied: %s (%d B/s)\n", ipStr, limit)
		}
	}
}

func parseFlowParams(r *http.Request) (FlowKey, string, string, uint16, error) {
	q := r.URL.Query()
	ipStr, protoStr, portStr := q.Get("ip"), q.Get("proto"), q.Get("port")
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return FlowKey{}, "", "", 0, fmt.Errorf("invalid ip")
	}
	var proto uint8
	switch protoStr {
	case "icmp":
		proto = 1
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	default:
		proto = 6
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	key := FlowKey{Ip: binary.BigEndian.Uint32(ip), Port: port, Protocol: proto, Pad: 0}
	return key, ipStr, protoStr, port, nil
}

func getProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
