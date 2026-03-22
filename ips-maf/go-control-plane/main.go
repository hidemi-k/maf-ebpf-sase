// Copyright (c) 2026 hidemi-k
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

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

type ResponseEntry struct {
	Ip       string  `json:"ip"`
	Port     uint16  `json:"port"`
	Protocol string  `json:"protocol"`
	Stats    IpStats `json:"stats"`
}

// --- ミティゲーション設定 ---
const (
	// SYNスパイク検知閾値: 3秒間のDelta
	synSpikeThreshold = 300
	// 連続検知回数でミティゲーション発動
	synSpikeCountTrigger = 2
	// QoS自動絞り帯域: 10KB/s（攻撃を減速・正常通信は維持）
	mitigationQosLimit = 10_000
	// 復旧判定: ミティゲーション適用後この時間安定したら解除
	mitigationRecoveryDuration = 2 * time.Minute
)

var (
	currentIface string
	currentMode  string
)

var (
	prevSynCounts = make(map[FlowKey]uint64)
	alertCounts   = make(map[FlowKey]int)
	// ミティゲーション適用済みIP → 適用時刻
	mitigatedAt = make(map[uint32]time.Time)
	synMutex    sync.Mutex
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

	l := attachXDPProgram(coll.Programs["xdp_filter"], iface.Index, xdpMode)
	defer l.Close()

	// マップへの参照取得
	statsMap := coll.Maps["STATS_MAP"]
	dropList := coll.Maps["DROP_LIST"]
	qosMap   := coll.Maps["QOS_MAP"]

	if statsMap == nil || dropList == nil || qosMap == nil {
		log.Fatal("Failed to load one or more eBPF maps")
	}

	log.Printf("✅ All eBPF maps loaded successfully")
	log.Printf("🛡️  Auto-mitigation: SYN spike >= %d (x%d) → QoS %d B/s → recovery after %v",
		synSpikeThreshold, synSpikeCountTrigger, mitigationQosLimit, mitigationRecoveryDuration)

	// SYNスパイク監視 + QoS自動ミティゲーション + 自動復旧ループ
	//
	// ゼロトラスト版との対応:
	//   ZT版: AUTH_IPS[ip].Priority = 1 (降格) → 2 (復旧)
	//   FW版: QOS_MAP[ip] = 10KB/s (絞り)    → Delete (復旧)
	//
	// 役割分担:
	//   Go (本ループ): QoSによる自動減速ミティゲーション（即時・自律）
	//   LLMオーケストレータ: DROP_LISTによるブロック（人間確認あり）
	go func(sMap *ebpf.Map, qMap *ebpf.Map) {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var key FlowKey
			var stats IpStats
			iter := sMap.Iterate()

			synMutex.Lock()
			for iter.Next(&key, &stats) {
				currentSyn := stats.SynPackets
				prevSyn := prevSynCounts[key]

				delta := uint64(0)
				if currentSyn >= prevSyn {
					delta = currentSyn - prevSyn
				} else {
					delta = currentSyn
				}

				srcIP := key.Ip

				if delta > synSpikeThreshold {
					alertCounts[key]++
					log.Printf("[Defense] 🚨 SYN Spike from %s port %d (Delta: %d, count: %d)",
						intToIP(srcIP), key.Port, delta, alertCounts[key])

					// 連続検知回数に達したらQoSミティゲーション発動
					if alertCounts[key] >= synSpikeCountTrigger {
						if _, alreadyMitigated := mitigatedAt[srcIP]; !alreadyMitigated {
							qosCfg := QosConfig{
								LimitBytesPerSec: mitigationQosLimit,
								Tokens:           mitigationQosLimit,
								LastUpdated:      0,
							}
							if err := qMap.Put(&srcIP, &qosCfg); err != nil {
								log.Printf("[Defense] ❌ QoS set failed for %s: %v", intToIP(srcIP), err)
							} else {
								mitigatedAt[srcIP] = time.Now()
								log.Printf("[Defense] 🛡️  Mitigated %s: QoS set to %d B/s (SYN spike x%d)",
									intToIP(srcIP), mitigationQosLimit, alertCounts[key])
							}
						}
					}
				} else {
					alertCounts[key] = 0

					// 復旧チェック: ミティゲーション適用済みIPの安定確認
					// deltaの大小に関わらず常に評価（ゼロトラスト版の修正を踏襲）
					if mitigTime, ok := mitigatedAt[srcIP]; ok {
						if time.Since(mitigTime) > mitigationRecoveryDuration {
							if err := qMap.Delete(&srcIP); err != nil {
								// すでに削除済み or 存在しない場合はスキップ
								log.Printf("[Recovery] ⚠️  QoS delete for %s: %v", intToIP(srcIP), err)
							} else {
								log.Printf("[Recovery] ✅ Restored %s: QoS mitigation lifted after %v",
									intToIP(srcIP), mitigationRecoveryDuration)
							}
							delete(mitigatedAt, srcIP)
						}
					}
				}

				prevSynCounts[key] = currentSyn
			}
			synMutex.Unlock()

			if err := iter.Err(); err != nil {
				log.Printf("⚠️ Iterator error: %v", err)
			}
		}
	}(statsMap, qosMap)

	// --- APIハンドラ登録 ---
	http.HandleFunc("/info", handleInfo)
	http.HandleFunc("/stats", handleGetStats(statsMap))
	http.HandleFunc("/top", handleTopStats(statsMap))
	http.HandleFunc("/drop/list", handleList(dropList))
	http.HandleFunc("/drop/block", handleBlock(dropList))
	http.HandleFunc("/drop/unblock", handleUnblock(dropList))
	http.HandleFunc("/qos/set", handleSetQoS(qosMap))
	http.HandleFunc("/qos/list", handleListQoS(qosMap))
	http.HandleFunc("/qos/get", handleGetQoS(qosMap))

	log.Printf("🚀 AIBN Agent running on %s", ifaceName)
	log.Printf("📊 API Endpoint: http://localhost:8080")
	log.Printf("📋 Available endpoints:")
	log.Printf("   GET /info - Get agent info (interface, xdp_mode, version)")
	log.Printf("   GET /stats - Get all flow statistics")
	log.Printf("   GET /top - Get top 10 flows by packet count")
	log.Printf("   GET /qos/set?ip=X.X.X.X&limit=BYTES_PER_SEC - Set QoS limit")
	log.Printf("   GET /drop/block?ip=X.X.X.X&proto=tcp|udp|icmp&port=PORT - Block flow")
	log.Printf("   GET /drop/unblock?ip=X.X.X.X&proto=tcp|udp|icmp&port=PORT - Unblock flow")
	log.Printf("   GET /drop/list - List blocked flows")
	log.Printf("   GET /qos/list - List all QoS policies (confirm auto-mitigation)")
	log.Printf("   GET /qos/get?ip=X.X.X.X - Get QoS policy for a specific IP")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

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
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
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

func handleListQoS(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type QosEntry struct {
			LimitBytesPerSec uint64 `json:"limit_bytes_per_sec"`
			Tokens           uint64 `json:"tokens"`
			LastUpdated      uint64 `json:"last_updated"`
		}
		var key uint32
		var val QosConfig
		entries := make(map[string]QosEntry)
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			ipStr := intToIP(key).String()
			entries[ipStr] = QosEntry{
				LimitBytesPerSec: val.LimitBytesPerSec,
				Tokens:           val.Tokens,
				LastUpdated:      val.LastUpdated,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

func handleGetQoS(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ipStr := r.URL.Query().Get("ip")
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			http.Error(w, "invalid ip", 400)
			return
		}
		key := binary.BigEndian.Uint32(ip)
		var val QosConfig
		if err := m.Lookup(&key, &val); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"ip":     ipStr,
				"status": "no QoS policy",
			})
			return
		}
		result := map[string]interface{}{
			"ip":                 ipStr,
			"limit_bytes_per_sec": val.LimitBytesPerSec,
			"tokens":             val.Tokens,
			"last_updated":       val.LastUpdated,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// --- ヘルパー関数 ---

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
