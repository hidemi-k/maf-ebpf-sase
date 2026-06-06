// Copyright (c) 2026 hidemi-k
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ---------------------------------------------------------------------------
// 定数・設定
// ---------------------------------------------------------------------------

const (
	version = "1.1.0"

	// CONFIG_MAP のキー（main.rs と同期すること）
	cfgKeyMagic    = uint32(0)
	cfgKeyDuration = uint32(1)
	cfgKeyPort     = uint32(2)

	defaultAuthDurationNs = uint64(300 * 1_000_000_000) // 300秒
	defaultAuthPort       = uint16(8888)
)

// ---------------------------------------------------------------------------
// 構造体定義（main.rs の #[repr(C)] と ABI を合わせること）
// ---------------------------------------------------------------------------

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

// AuthLog は認証イベントを記録する。
// Magic フィールドには平文の magic 値を保存しない（マスク済みハッシュのみ）。
type AuthLog struct {
	Timestamp time.Time `json:"timestamp"`
	RemoteIP  string    `json:"remote_ip"`
	MagicHash string    `json:"magic_hash"` // SHA-256 の先頭16文字（平文不保存）
	Action    string    `json:"action"`
}

// ---------------------------------------------------------------------------
// グローバル状態
// ---------------------------------------------------------------------------

var (
	authHistory []AuthLog
	logMu       sync.Mutex

	currentIface string
	currentMode  string

	// チケット発行ロック（/auth/lock で true にすると再起動まで発行禁止）
	ticketLocked bool
	ticketMu     sync.Mutex

	// revoke 済み IP のブラックリスト（ip(uint32) → revoke 時刻）
	revokeBlacklist = make(map[uint32]time.Time)
	blacklistMu     sync.RWMutex

	// blacklistDuration は環境変数 BLACKLIST_DURATION_SEC で上書き可能
	blacklistDuration = mustParseDuration("BLACKLIST_DURATION_SEC", 10*time.Minute)
)

// mustParseDuration は環境変数から秒数を読み、失定値 d を返す。
func mustParseDuration(envKey string, d time.Duration) time.Duration {
	s := os.Getenv(envKey)
	if s == "" {
		return d
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		log.Printf("⚠️  Invalid %s=%q, using default %s", envKey, s, d)
		return d
	}
	return time.Duration(n) * time.Second
}

// ---------------------------------------------------------------------------
// 認証ミドルウェア
// ---------------------------------------------------------------------------

// agentAPIKey は環境変数 AGENT_API_KEY から読む。
// 空の場合はミドルウェアを無効化し、起動時に警告を出す。
var agentAPIKey = os.Getenv("AGENT_API_KEY")

// authMiddleware は書き込み系エンドポイントに適用するトークン認証。
// AGENT_API_KEY が未設定の場合はすべてのリクエストを許可する（開発環境向け）。
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if agentAPIKey == "" {
			next(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key != agentAPIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("🔒 Unauthorized API access: remote=%s path=%s", r.RemoteAddr, r.URL.Path)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// magic ハッシュ（ログ記録用）
// ---------------------------------------------------------------------------

// maskMagic は magic 値を SHA-256 でハッシュし、先頭16文字を返す。
// 元の magic 値は一切ログに残らない。
func maskMagic(magic string) string {
	h := sha256.Sum256([]byte(magic))
	return fmt.Sprintf("sha256:%x", h[:8]) // 先頭8バイト = 16文字
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	ifaceFlag   := flag.String("iface",    "",     "Network interface name (required)")
	xdpModeFlag := flag.String("xdp-mode", "auto", "XDP mode: native, generic, or auto")
	flag.Parse()

	if *ifaceFlag == "" {
		log.Fatal("Usage: sudo ./sase-agent -iface <iface> [-xdp-mode native|generic|auto]")
	}

	xdpMode   := validateXDPMode(*xdpModeFlag)
	ifaceName := *ifaceFlag
	currentIface = ifaceName
	currentMode  = xdpMode

	if agentAPIKey == "" {
		log.Printf("⚠️  AGENT_API_KEY is not set — write APIs are unprotected (dev mode)")
	} else {
		log.Printf("✅ API key authentication enabled")
	}
	log.Printf("✅ Interface: %s, XDP Mode: %s", ifaceName, xdpMode)
	log.Printf("✅ Blacklist duration: %s", blacklistDuration)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed to remove memlock limit:", err)
	}

	// eBPF オブジェクトファイルを探す
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
		log.Fatalf("failed to load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create collection: %v", err)
	}
	defer coll.Close()

	if coll.Programs["xdp_filter"] == nil {
		log.Fatal("xdp_filter program not found in eBPF object")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to find interface %s: %v", ifaceName, err)
	}

	l := attachXDPProgram(coll.Programs["xdp_filter"], iface.Index, xdpMode)
	defer l.Close()

	statsMap      := coll.Maps["STATS_MAP"]
	authIps       := coll.Maps["AUTH_IPS"]
	dropList      := coll.Maps["DROP_LIST"]
	qosMap        := coll.Maps["QOS_MAP"]
	configMap     := coll.Maps["CONFIG_MAP"]
	redirectConfig := coll.Maps["REDIRECT_CONFIG"]

	for name, m := range map[string]*ebpf.Map{
		"STATS_MAP": statsMap, "AUTH_IPS": authIps,
		"DROP_LIST": dropList, "QOS_MAP": qosMap,
		"CONFIG_MAP": configMap, "REDIRECT_CONFIG": redirectConfig,
	} {
		if m == nil {
			log.Fatalf("eBPF map %s not found", name)
		}
	}
	log.Printf("✅ All eBPF maps loaded")

	// CONFIG_MAP 初期値の書き込み
	// 注意: Go の const はアドレスを取れないため、ローカル変数にコピーして渡す
	cfgDurationKey := cfgKeyDuration
	cfgDurationVal := defaultAuthDurationNs
	if err := configMap.Put(&cfgDurationKey, &cfgDurationVal); err != nil {
		log.Printf("⚠️  Failed to set CONFIG_MAP[duration]: %v", err)
	} else {
		log.Printf("✅ AUTH duration set: 300s")
	}

	cfgPortKey := cfgKeyPort
	authPortVal := uint64(defaultAuthPort)
	if err := configMap.Put(&cfgPortKey, &authPortVal); err != nil {
		log.Printf("⚠️  Failed to set CONFIG_MAP[port]: %v", err)
	} else {
		log.Printf("✅ AUTH port set: %d", defaultAuthPort)
	}

	// xdp0 へのリダイレクト設定
	if xdp0, err := net.InterfaceByName("xdp0"); err != nil {
		log.Printf("⚠️  xdp0 not found: %v (redirect → XDP_PASS fallback)", err)
	} else {
		cfg := RedirectConfig{Ifindex: uint32(xdp0.Index)}
		key := uint32(0)
		if err := redirectConfig.Put(&key, &cfg); err != nil {
			log.Printf("⚠️  Failed to set REDIRECT_CONFIG: %v", err)
		} else {
			log.Printf("✅ Redirect target: xdp0 (ifindex=%d)", xdp0.Index)
		}
	}

	// 自律防御ループ（SYN スパイク検知・格下げ・自動復旧）
	go runDefenseLoop(statsMap, authIps)

	// API ルート登録
	// 読み取り系: 認証不要
	http.HandleFunc("/info",             handleInfo)
	http.HandleFunc("/stats",            handleGetStats(statsMap))
	http.HandleFunc("/top",              handleTopStats(statsMap))
	http.HandleFunc("/config",           handleConfig(configMap))
	http.HandleFunc("/auth/logs",        handleGetAuthLogs)
	http.HandleFunc("/auth/identities",  handleGetIdentities(authIps))
	http.HandleFunc("/auth/blacklist",   handleGetBlacklist)
	http.HandleFunc("/drop/list",        handleList(dropList))

	// 書き込み系: authMiddleware で保護
	http.HandleFunc("/auth/ticket",   authMiddleware(handleIssueTicket(configMap)))
	http.HandleFunc("/auth/revoke",   authMiddleware(handleClearIdentity(authIps)))
	http.HandleFunc("/auth/lock",     authMiddleware(handleLockTicket))
	http.HandleFunc("/auth/priority", authMiddleware(handleSetPriority(authIps, qosMap)))
	http.HandleFunc("/drop/block",    authMiddleware(handleBlock(dropList)))
	http.HandleFunc("/drop/unblock",  authMiddleware(handleUnblock(dropList)))
	http.HandleFunc("/qos/set",       authMiddleware(handleSetQoS(qosMap)))

	log.Printf("🚀 AIBN Agent running on interface=%s", ifaceName)
	log.Printf("📊 API: http://localhost:8080")
	log.Printf("   [Read]  GET /info /stats /top /config /auth/logs /auth/identities /auth/blacklist /drop/list")
	log.Printf("   [Write] POST/GET with X-API-Key header: /auth/ticket /auth/revoke /auth/lock /auth/priority /drop/block /drop/unblock /qos/set")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// 自律防御ループ
// ---------------------------------------------------------------------------

// runDefenseLoop は 3 秒ごとに STATS_MAP を走査し、
// SYN スパイク（delta > 300/interval を2回連続検知）で Priority を 1 に格下げ、
// 1 分後に自動復旧する。
func runDefenseLoop(sMap *ebpf.Map, aMap *ebpf.Map) {
	prevSynCounts := make(map[FlowKey]uint64)
	alertCounts   := make(map[FlowKey]int)
	isolatedAt    := make(map[uint32]time.Time)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key   FlowKey
		var stats IpStats
		iter := sMap.Iterate()

		for iter.Next(&key, &stats) {
			currentSyn := stats.SynPackets
			prevSyn    := prevSynCounts[key]

			delta := currentSyn - prevSyn
			if currentSyn < prevSyn {
				delta = currentSyn // カウンタロールオーバー対策
			}

			if delta > 300 {
				alertCounts[key]++
				if alertCounts[key] >= 2 {
					var auth AuthInfo
					if err := aMap.Lookup(key.Ip, &auth); err == nil && auth.Priority > 1 {
						auth.Priority = 1
						_ = aMap.Put(key.Ip, &auth)
						isolatedAt[key.Ip] = time.Now()
						log.Printf("[Defense] 🚨 Isolated %s port=%d delta=%d",
							intToIP(key.Ip), key.Port, delta)
					}
				}
			} else {
				alertCounts[key] = 0
			}

			// 復旧チェック（delta の大小に関わらず常に評価する）
			if isoTime, ok := isolatedAt[key.Ip]; ok && time.Since(isoTime) > time.Minute {
				var auth AuthInfo
				if err := aMap.Lookup(key.Ip, &auth); err == nil && auth.Priority == 1 {
					auth.Priority = 2
					_ = aMap.Put(key.Ip, &auth)
					delete(isolatedAt, key.Ip)
					log.Printf("[Recovery] ✅ Restored %s", intToIP(key.Ip))
				}
			}

			prevSynCounts[key] = currentSyn
		}

		if err := iter.Err(); err != nil {
			log.Printf("⚠️ Iterator error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// XDP アタッチ
// ---------------------------------------------------------------------------

func validateXDPMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "native", "generic", "auto", "":
		if mode == "" {
			return "auto"
		}
		return mode
	default:
		log.Fatalf("Invalid -xdp-mode: %q. Use native, generic, or auto.", mode)
		return ""
	}
}

func attachXDPProgram(prog *ebpf.Program, ifindex int, mode string) link.Link {
	attach := func(flags link.XDPAttachFlags, label string) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     flags,
		})
	}

	switch mode {
	case "native":
		l, err := attach(link.XDPDriverMode, "Native")
		if err != nil {
			log.Fatalf("❌ XDP Native attach failed: %v", err)
		}
		log.Printf("✅ XDP attached (Native mode)")
		return l

	case "generic":
		l, err := attach(link.XDPGenericMode, "Generic")
		if err != nil {
			log.Fatalf("❌ XDP Generic attach failed: %v", err)
		}
		log.Printf("✅ XDP attached (Generic mode)")
		return l

	default: // auto
		l, err := attach(link.XDPDriverMode, "Native")
		if err != nil {
			log.Printf("⚠️  Native failed, falling back to Generic: %v", err)
			l, err = attach(link.XDPGenericMode, "Generic")
			if err != nil {
				log.Fatalf("❌ XDP attach failed (native+generic): %v", err)
			}
			log.Printf("✅ XDP attached (Generic fallback)")
			return l
		}
		log.Printf("✅ XDP attached (Native mode)")
		return l
	}
}

// ---------------------------------------------------------------------------
// API ハンドラ
// ---------------------------------------------------------------------------

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"interface": currentIface,
		"xdp_mode":  currentMode,
		"timestamp": time.Now().Unix(),
		"version":   version,
		"note":      "VPP determines zero-copy or copy mode via af_xdp based on NIC capabilities",
	})
}

// handleIssueTicket は magic チケットを CONFIG_MAP[0] に書き込む。
// magic はログに平文で記録せず、SHA-256 ハッシュ（先頭16文字）のみ保存する。
func handleIssueTicket(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ロック確認
		ticketMu.Lock()
		locked := ticketLocked
		ticketMu.Unlock()
		if locked {
			http.Error(w, "Ticket issuance is locked. Restart agent to unlock.", http.StatusForbidden)
			log.Printf("🔒 Ticket rejected (locked): remote=%s", r.RemoteAddr)
			return
		}

		// magic パース（0x プレフィックスあり・なし両対応）
		valStr := r.URL.Query().Get("magic")
		var magic uint64
		if _, err := fmt.Sscanf(valStr, "0x%x", &magic); err != nil {
			if _, err2 := fmt.Sscanf(valStr, "%x", &magic); err2 != nil {
				http.Error(w, "Invalid hex format", http.StatusBadRequest)
				return
			}
		}

		// magic=0 は番兵値のため禁止
		if magic == 0 {
			http.Error(w, "magic=0 is reserved", http.StatusBadRequest)
			log.Printf("⚠️  Rejected magic=0: remote=%s", r.RemoteAddr)
			return
		}

		// ブラックリスト確認
		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP := net.ParseIP(remoteHost).To4(); remoteIP != nil {
			key := binary.BigEndian.Uint32(remoteIP)
			blacklistMu.RLock()
			revokedAt, inBL := revokeBlacklist[key]
			blacklistMu.RUnlock()
			if inBL && time.Since(revokedAt) < blacklistDuration {
				http.Error(w, "Source IP is blacklisted", http.StatusForbidden)
				log.Printf("🚫 Ticket rejected (blacklisted): remote=%s", r.RemoteAddr)
				return
			}
		}

		// CONFIG_MAP[0] に書き込み
		key := cfgKeyMagic
		if err := m.Put(&key, &magic); err != nil {
			http.Error(w, "Failed to write magic", http.StatusInternalServerError)
			log.Printf("❌ CONFIG_MAP write failed: %v", err)
			return
		}

		// ログには magic のハッシュのみ記録（平文を残さない）
		mh := maskMagic(valStr)
		logMu.Lock()
		authHistory = append(authHistory, AuthLog{
			Timestamp: time.Now(),
			RemoteIP:  r.RemoteAddr,
			MagicHash: mh,
			Action:    "TICKET_ISSUED",
		})
		logMu.Unlock()

		log.Printf("🎫 Ticket issued: hash=%s remote=%s", mh, r.RemoteAddr)
		fmt.Fprintf(w, "Ticket active (hash=%s)\n", mh)
	}
}

// handleLockTicket はチケット発行を永続的に禁止する（再起動まで解除不可）。
func handleLockTicket(w http.ResponseWriter, r *http.Request) {
	ticketMu.Lock()
	ticketLocked = true
	ticketMu.Unlock()
	log.Printf("🔒 Ticket issuance LOCKED by %s", r.RemoteAddr)
	fmt.Fprintf(w, "Ticket issuance locked until agent restart.\n")
}

func handleGetBlacklist(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		IP        string `json:"ip"`
		RevokedAt string `json:"revoked_at"`
		ExpiresIn string `json:"expires_in"`
	}
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()

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
	writeJSON(w, entries)
}

func handleGetAuthLogs(w http.ResponseWriter, r *http.Request) {
	logMu.Lock()
	defer logMu.Unlock()
	writeJSON(w, authHistory)
}

func handleConfig(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// const はアドレスを取れないためローカル変数にコピーする
		keyMagic    := cfgKeyMagic
		keyDuration := cfgKeyDuration
		keyPort     := cfgKeyPort
		var magic, duration, port uint64
		_ = m.Lookup(&keyMagic, &magic)
		_ = m.Lookup(&keyDuration, &duration)
		_ = m.Lookup(&keyPort, &port)

		// magic の現在値は参照状態のみ返す（値自体は返さない）
		magicStatus := "unset"
		switch magic {
		case 0:
			magicStatus = "unset"
		case ^uint64(0): // u64::MAX
			magicStatus = "consumed"
		default:
			magicStatus = "active"
		}

		writeJSON(w, map[string]interface{}{
			"magic_status":     magicStatus,
			"auth_duration_ns": duration,
			"auth_port":        port & 0xFFFF,
		})
	}
}

func handleClearIdentity(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ipStr := r.URL.Query().Get("ip")
		ip    := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
		key := binary.BigEndian.Uint32(ip)

		_ = m.Delete(&key)

		blacklistMu.Lock()
		revokeBlacklist[key] = time.Now()
		blacklistMu.Unlock()

		logMu.Lock()
		authHistory = append(authHistory, AuthLog{
			Timestamp: time.Now(),
			RemoteIP:  r.RemoteAddr,
			MagicHash: "-",
			Action:    "REVOKED_AND_BLACKLISTED:" + ipStr,
		})
		logMu.Unlock()

		log.Printf("🚫 Revoked+blacklisted: %s (duration: %s)", ipStr, blacklistDuration)
		fmt.Fprintf(w, "Revoked and blacklisted: %s (%s)\n", ipStr, blacklistDuration)
	}
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
			results[intToIP(key).String()] = val
		}
		if err := iter.Err(); err != nil {
			log.Printf("⚠️ Iteration error: %v", err)
		}
		writeJSON(w, results)
	}
}

func handleSetPriority(authMap *ebpf.Map, qosMap *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q      := r.URL.Query()
		ipStr  := q.Get("ip")
		ip     := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}

		var level uint32
		fmt.Sscanf(q.Get("level"), "%d", &level)
		if level < 1 || level > 3 {
			http.Error(w, "level must be 1(Bulk), 2(Normal), or 3(VIP)", http.StatusBadRequest)
			return
		}

		key := binary.BigEndian.Uint32(ip)
		var auth AuthInfo
		if err := authMap.Lookup(&key, &auth); err != nil {
			http.Error(w, "Identity not found", http.StatusNotFound)
			return
		}
		auth.Priority = level
		_ = authMap.Put(&key, &auth)

		log.Printf("[EVENT] TYPE=PRIORITY_CHANGE IP=%s LEVEL=%d", ipStr, level)
		fmt.Fprintf(w, "Set %s → Priority %d\n", ipStr, level)
	}
}

func handleGetStats(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := collectStats(m)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Ip < entries[j].Ip })
		writeJSON(w, entries)
	}
}

func handleTopStats(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := collectStats(m)
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Stats.Packets > entries[j].Stats.Packets
		})
		limit := 10
		if len(entries) < limit {
			limit = len(entries)
		}
		writeJSON(w, entries[:limit])
	}
}

func handleList(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var key FlowKey
		var val uint32
		entries := make(map[string]string)
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			k := fmt.Sprintf("%s:%d [%s]", intToIP(key.Ip), key.Port, getProtoName(key.Protocol))
			entries[k] = "BLOCKED"
		}
		writeJSON(w, entries)
	}
}

func handleBlock(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ipStr, protoStr, port, err := parseFlowParams(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		val := uint32(1)
		_ = m.Put(&key, &val)
		fmt.Fprintf(w, "Blocked: %s %s:%d\n", protoStr, ipStr, port)
	}
}

func handleUnblock(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, _, _, _, _ := parseFlowParams(r)
		_ = m.Delete(&key)
		fmt.Fprintf(w, "Unblocked\n")
	}
}

func handleSetQoS(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q     := r.URL.Query()
		ipStr := q.Get("ip")
		var limit uint64
		fmt.Sscanf(q.Get("limit"), "%d", &limit)
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
		key    := binary.BigEndian.Uint32(ip)
		config := QosConfig{LimitBytesPerSec: limit, Tokens: limit, LastUpdated: 0}
		_ = m.Put(&key, &config)
		fmt.Fprintf(w, "QoS applied: %s (%d B/s)\n", ipStr, limit)
	}
}

// ---------------------------------------------------------------------------
// ユーティリティ
// ---------------------------------------------------------------------------

func collectStats(m *ebpf.Map) []ResponseEntry {
	var key FlowKey
	var val IpStats
	var entries []ResponseEntry
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

func parseFlowParams(r *http.Request) (FlowKey, string, string, uint16, error) {
	q                       := r.URL.Query()
	ipStr, protoStr, portStr := q.Get("ip"), q.Get("proto"), q.Get("port")
	ip                      := net.ParseIP(ipStr).To4()
	if ip == nil {
		return FlowKey{}, "", "", 0, fmt.Errorf("invalid ip")
	}
	var proto uint8
	switch protoStr {
	case "icmp":
		proto = 1
	case "udp":
		proto = 17
	default: // tcp
		proto = 6
		protoStr = "tcp"
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	key := FlowKey{Ip: binary.BigEndian.Uint32(ip), Port: port, Protocol: proto}
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

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
