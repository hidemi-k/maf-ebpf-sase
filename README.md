# Autonomous AI-SASE Framework with eBPF & Multi-Agents

> Autonomous threat detection and response: eBPF monitors the kernel, MAF-powered LLM agents decide the action, Go/Rust enforces it at line rate — no human in the loop.

All AI orchestration is unified on **Microsoft Agent Framework (MAF)**.

## 📺 Demo

### ZTNA — Autonomous threat blocking (60 sec)
https://github.com/user-attachments/assets/9774ace3-6f57-48ba-8968-17508a5c07c0

### IPS — Human-in-the-loop enforcement (53 sec)
https://github.com/user-attachments/assets/7928db18-4297-4fdc-bc64-0882d5dfc21b

## 🏗 Architecture

```
  [ Threats / Traffic ]
         │
  ┌──────▼──────────────────────────────────────────────────────────┐
  │  Data Plane: Rust + eBPF/XDP                                    │
  │  Tetragon (kernel syscall monitor)  Elasticsearch (log store)   │
  └──────┬────────────────────────────────────┬─────────────────────┘
         │ stats / XDP maps                   │ security events
  ┌──────▼──────────────┐     ┌───────────────▼────────────────────────┐
  │  Control Plane (Go) │◄────│           MAF Orchestration            │
  │  REST API           │     │  ┌──────────────┐  ┌────────────────┐  │
  │  X-API-Key auth     │     │  │ Admin agent  │  │  SASE agent    │  │
  └─────────────────────┘     │  ├──────────────┤  ├────────────────┤  │
                              │  │ Tetragon mon │  │ Ticket/Policy  │  │
  ┌─────────────────────┐     │  │ Rate monitor │  │ management     │  │
  │  Infra: Containerlab│     │  └──────────────┘  └────────────────┘  │
  │  VPP + Juniper cRPD │     │         │  Llama-3.3-70b via Groq API  │
  └─────────────────────┘     └─────────┴──────────────────────────────┘
                                         │
                              ┌──────────▼──────────────────────────────┐
                              │  A2A Protocol (next phase)              │
                              │  a2a-ceos-core: Arista                  │
                              └─────────────────────────────────────────┘
```

## 🧠 Why Microsoft Agent Framework (MAF)?

All AI orchestration is unified under **MAF** (`agent_framework`):

- **Native tool dispatch**: MAF automatically invokes tools from function signatures + docstrings.
- **Session & history management**: Conversation history and token limits are delegated to the MAF session layer.
- **Unified LLM interface**: Works seamlessly with Groq-hosted Llama-3 models via the OpenAI-compatible API.
- **Consistent error handling**: Rate limits, bad requests, and retries are handled by the MAF layer.

The same MAF-based agent pattern is used across all modules — from low-level XDP security enforcement to high-level network configuration management.

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| **AI Orchestration** | Microsoft Agent Framework (MAF) |
| **LLM Backend** | Llama-3.3-70b-versatile (via Groq API, OpenAI-compatible) |
| **Data Plane** | Rust + eBPF/XDP — line-rate packet filtering |
| **Control Plane** | Go — XDP map management & policy REST API |
| **Kernel Monitor** | Tetragon (eBPF-based syscall tracing) |
| **Log Store** | Elasticsearch (Tetragon event streaming & RAG) |
| **Infrastructure** | Containerlab + VPP + Juniper cRPD/vevo |
| **Multi-vendor (next)** | A2A Protocol — Arista cEOS / Cisco / Junos |

## 📁 Directory Structure

```
my-sase-project/
├── config.ini.example                        # API key template (copy to config.ini)
├── infra/
│   └── containerlab/
│       └── vpp.clab.yml                      # Containerlab topology definition
├── ips-maf/                                  # IPS module — human-in-the-loop enforcement (MAF)
│   ├── go-control-plane/
│   │   ├── go.mod
│   │   └── main.go
│   ├── python-agents/
│   │   ├── api_spec.py
│   │   └── sase_agent.py
│   └── xdp-ebpf/
│       ├── Cargo.toml
│       └── main.rs
├── netmiko-maf/                              # Network fault diagnosis via Netmiko + MAF (Jupyter)
│   └── network_diagnostic_agent.ipynb        # 5-agent diagnostic pipeline (L2/L3/Self-Correction)
├── LICENSE
├── README.md
└── ztna-tetragon-maf/                        # ZTNA module — autonomous blocking (MAF)
    ├── go-control-plane/
    │   ├── go.mod
    │   └── main.go                           # REST API + XDP map management
    ├── python-agents/
    │   ├── admin_agent_maf.py                # Security admin agent (MAF)
    │   ├── api_spec.py
    │   └── sase_agent_maf.py                 # User-facing SASE agent (MAF)
    ├── tetragon/
    │   └── block-shadow-access.template.yaml # Tetragon policy: blocks shadow /etc/passwd access
    └── xdp-ebpf/
        ├── Cargo.toml
        └── main.rs                           # Rust/XDP line-rate packet filter
```

> **Removed**: `netconf-rag-maf/netconf_rag_agent_framework.ipynb`
> In favour of the A2A-based multi-vendor approach.

### Tetragon policy

`ztna-tetragon-maf/tetragon/block-shadow-access.template.yaml` is a [Tetragon](https://tetragon.io/) `TracingPolicy` that detects and blocks unauthorized access to `/etc/shadow` and `/etc/passwd` at the kernel level via eBPF.

When Tetragon fires a `KPROBE_ACTION_SIGKILL` event, the **admin agent (MAF)** picks it up, streams the event to **Elasticsearch** for evidence preservation, reasons about the threat, and instructs the Go control plane to revoke the ZTNA session and blacklist the attacker — no human intervention required.

## 🔬 Orchestration: Multi-Layer Diagnostics

### [`netmiko-maf/`](./netmiko-maf/) — Multi-layer fault diagnosis across vendors

| Agent | Role |
|---|---|
| Command selector | Chooses the right command set from symptom description |
| L2 analyst | Detects interface and MAC-level anomalies |
| L3 analyst | Identifies routing and ARP issues |
| Consistency checker | Cross-validates L2/L3 state, applies Self-Correction |
| Report generator | Produces structured findings with evidence citations |

- **Multi-vendor by design**: `VENDOR_KEY` decouples the SSH driver from the command dictionary — adding a new device type requires only a YAML entry.
- **Mock mode**: All agents run against mock data without physical devices, enabling CI/CD-friendly testing.

## 🔗 A2A Migration (Next Phase)

The NETCONF RAG notebook has been deprecated. The replacement is an **A2A (Agent-to-Agent) protocol**-based architecture implemented in [`a2a-ceos-core`](https://github.com/hidemi-k/a2a-ceos-core):

## 🏁 Getting Started

### Prerequisites

| Tool | Version | Link |
|---|---|---|
| Microsoft Agent Framework | latest | `pip install agent-framework` |
| Groq API Key | — | [console.groq.com](https://console.groq.com) |
| Go | 1.21+ | [go.dev](https://go.dev/dl/) |
| Rust + cargo | stable | [rustup.rs](https://rustup.rs) |
| Containerlab | latest | [containerlab.dev](https://containerlab.dev) |

### Setup

1. **Deploy the Topology**:
    ```bash
    sudo containerlab deploy -t infra/containerlab/vpp.clab.yml
    ```

2. **Setup API Keys**:
    ```bash
    cp config.ini.example config.ini
    # Edit config.ini and set GROQ_API_KEY
    ```
    Optional — enable write API authentication:
    ```bash
    export AGENT_API_KEY=$(openssl rand -hex 32)
    ```

3. **Build and Launch Go Control Plane**:
    ```bash
    cd ztna-tetragon-maf/xdp-ebpf
    cargo build --release
    cp target/bpfel-unknown-none/release/xdp-ebpf ../go-control-plane/main.o
    cd ../go-control-plane
    sudo nsenter -t $PID -n ./sase-agent -iface eth3 -xdp-mode generic
    ```

4. **Run the MAF Agents**:
    ```bash
    python3 ztna-tetragon-maf/python-agents/admin_agent_maf.py
    python3 ztna-tetragon-maf/python-agents/sase_agent_maf.py
    python3 ips-maf/python-agents/sase_agent.py
    ```

5. **Explore the Notebooks**:
    - [`netmiko-maf/`](./netmiko-maf/) — Network diagnostics powered by MAF agents

> The NETCONF×RAG GUI app is available separately:
> [maf-netconf-rag-gui](https://github.com/hidemi-k/maf-netconf-rag-gui)

## ⚠️ Known Limitations

### MAF: asyncio ContextVar in Synchronous Threads

When calling `Agent.run()` from a synchronous thread via `asyncio.run()`, MAF may raise:

```
ContextVar was created in a different Context
```

This project works around it by replacing `asyncio.run(Agent.run())` with direct `requests.post()` to the Groq API for non-interactive LLM calls (`AdminNarrator`, `FWAnalyst`). Interactive chat (`sase_agent_maf.py`) uses `asyncio.run(chat_loop())` → `await agent.run()` and is unaffected.

### MAF Native HITL: Tool Call Instability with Open Models

The IPS module implements human-in-the-loop (HITL) using a custom `[EXEC:]` tag parsing approach rather than MAF's native `approval_mode="always_require"` API.

`llama-3.3-70b-versatile` via Groq does not reliably generate tool call JSON in MAF's HITL context. MAF's HITL mechanism is correctly designed; the limitation lies in the model. Using MAF-native HITL requires a model with stable tool calling support such as Claude.

## 📄 License

[MIT License](./LICENSE) © 2026 hidemi-k
