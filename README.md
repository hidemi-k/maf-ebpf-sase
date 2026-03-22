# Autonomous AI-SASE Framework with eBPF & Multi-Agents

> Autonomous threat detection and response: eBPF monitors the kernel, MAF-powered LLM agents decide the action, Go/Rust enforces it at line rate — no human in the loop.

All AI orchestration is unified on **Microsoft Agent Framework (MAF) rc5**. Tested on MAF rc5; may require changes for GA.

## 📺 Demo

### ZTNA — Autonomous threat blocking (60 sec)
https://github.com/user-attachments/assets/9774ace3-6f57-48ba-8968-17508a5c07c0

### IPS — Human-in-the-loop enforcement (53 sec)
https://github.com/user-attachments/assets/7928db18-4297-4fdc-bc64-0882d5dfc21b

## 🏗 Architecture

```
  [ Threats / Traffic ]
         │
  ┌──────▼──────────────────────────────────────────────────┐
  │  Data Plane: Rust + eBPF/XDP   │  Tetragon (kernel mon) │
  └──────┬──────────────────────────────────┬───────────────┘
         │ stats / events                   │ security events
  ┌──────▼──────────────┐     ┌─────────────▼──────────────────────────┐
  │  Control Plane (Go) │◄────│         MAF rc5 Orchestration           │
  │  REST API + XDP map │     │  ┌──────────────┐  ┌────────────────┐  │
  └─────────────────────┘     │  │ Admin agent  │  │  SASE agent    │  │
                               │  ├──────────────┤  ├────────────────┤  │
  ┌─────────────────────┐     │  │ Netmiko agent│  │ NETCONF+RAG    │  │
  │  Infra: Containerlab│     │  └──────────────┘  └────────────────┘  │
  │  VPP + Juniper cRPD │     │         │  Llama-3 via Groq API         │
  └─────────────────────┘     └─────────┴──────────────────────────────┘
```

## 🚀 Evolution of the Project

This framework was developed through iterative experimentation (documented in the notebooks):

- **Phase 1–5**: Evolution from simple log analysis to reactive policy enforcement.
- **Phase 6**: Orchestrator decomposes natural language intent into a DAG of tasks and dispatches them to Workers in dependency order.
- **Phase 7 (Current)**: Four safety boundary layers added to the Orchestrator-Worker pattern — PolicyChecker, ValidationAgent, RollbackOrchestrator, and AuditLogger — for production-grade reliability.

## 🧠 Why Microsoft Agent Framework (MAF rc5)?

All AI orchestration is unified under **MAF rc5** (`agent_framework`). This was a deliberate architectural choice:

- **Native tool dispatch**: MAF automatically invokes tools from function signatures + docstrings — no manual dispatcher needed.
- **Session & history management**: Conversation history and token limits are delegated to the MAF session layer.
- **Unified LLM interface**: `OpenAIChatClient` with MAF's `model_id` spec works seamlessly with Groq-hosted Llama-3 models via the OpenAI-compatible API.
- **Consistent error handling**: Rate limits, bad requests, and retries are handled by the MAF layer across all agents.

The same MAF-based agent pattern is used across all four modules — from low-level XDP security enforcement to high-level NETCONF/RAG configuration management.

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| **AI Orchestration** | Microsoft Agent Framework (MAF) rc5 |
| **LLM Backend** | Llama-3 (via Groq API, OpenAI-compatible) |
| **Data Plane** | Rust + eBPF/XDP — line-rate packet filtering |
| **Control Plane** | Go — kernel map management & policy REST API |
| **Infrastructure** | Containerlab + VPP + Juniper cRPD/vevo |

## 📁 Directory Structure

```
my-sase-project/
├── config.ini.example                        # API key template (copy to config.ini)
├── infra/
│   └── containerlab/
│       └── vpp.clab.yml                      # Containerlab topology definition
├── ips-maf/                                  # IPS module — human-in-the-loop enforcement (MAF rc5)
│   ├── go-control-plane/
│   │   ├── go.mod
│   │   └── main.go
│   ├── python-agents/
│   │   ├── api_spec.py
│   │   └── sase_agent.py
│   └── xdp-ebpf/
│       ├── Cargo.toml
│       └── main.rs
├── netconf-rag-maf/                          # NETCONF config generation with RAG + MAF (Jupyter)
│   ├── netconf_rag_agent_framework.ipynb
│   └── policy.yaml                           # NETCONF agent policy (allowed interfaces, VLANs, forbidden XML ops)
├── netmiko-maf/                              # Network automation via Netmiko + MAF (Jupyter)
│   ├── netmiko_agent_framework.ipynb         # MAF rc5 agent implementation
│   └── network_diagnostic_agent_v5.ipynb     # Diagnostic agent (evolution from v1–v5)
├── LICENSE
├── README.md
└── ztna-tetragon-maf/                        # ZTNA module — autonomous blocking (MAF rc5)
    ├── go-control-plane/
    │   ├── go.mod
    │   └── main.go                           # REST API + XDP map management
    ├── python-agents/
    │   ├── admin_agent_maf.py                # Security admin agent (MAF rc5)
    │   ├── api_spec.py
    │   └── sase_agent_maf.py                 # User-facing SASE agent (MAF rc5)
    ├── tetragon/
    │   └── block-shadow-access.template.yaml # Tetragon policy: blocks shadow /etc/passwd access
    └── xdp-ebpf/
        ├── Cargo.toml
        └── main.rs                           # Rust/XDP line-rate packet filter
```

### Tetragon policy

`ztna-tetragon-maf/tetragon/block-shadow-access.template.yaml` is a [Tetragon](https://tetragon.io/) `TracingPolicy` that detects and blocks unauthorized access to `/etc/shadow` and `/etc/passwd` at the kernel level via eBPF.
When Tetragon fires an event matching this policy, the **admin agent (MAF rc5)** picks it up, reasons about the threat, and instructs the Go control plane to update the XDP drop map in real time — no human intervention required.

### NETCONF operation policy

`netmiko-maf/policy.yaml` is a NETCONF agent policy that declaratively defines the scope of allowed operations — permitted interfaces, VLAN ID ranges, forbidden XML keywords (e.g. `delete-config`, `kill-session`), allowed `<configuration>` nodes, and max VLAN operations per run. Operational constraints can be adjusted here without touching any Python code.

## 🔬 Orchestration: RAG + NETCONF + Multi-Layer Diagnostics

This project covers the network operations loop through two Jupyter notebooks.

### [`netconf-rag-maf/`](./netconf-rag-maf/netconf_rag_agent_framework.ipynb) — Permanent remediation via NETCONF × RAG

- **Why RAG?** LLMs do not have reliable knowledge of vendor-specific NETCONF schemas and CLI syntax. RAG injects the relevant device documentation at inference time, enabling accurate XML config generation for Juniper and other vendors.
- **Why NETCONF?** NETCONF rewrites the router's running configuration directly — enabling intent-based, permanent network changes.
- **Orchestrator-Worker pattern**: Natural language intent (e.g. *"delete VLAN70 and create VLAN100"*) is decomposed into a DAG of tasks by the Orchestrator, then dispatched to Worker agents in dependency order. Each Worker runs the full `get_inventory → translate → generate → validate → fix → deploy → audit` cycle independently.

### [`netmiko-maf/`](./netmiko-maf/network_diagnostic_agent_v5.ipynb) — Multi-layer fault diagnosis across vendors

A multi-agent diagnostic system for correlating L2 and L3 state across devices. Understanding network faults requires input from multiple layers simultaneously — this notebook provides a 5-agent pipeline for that:

| Agent | Role |
|---|---|
| Command selector | Chooses the right command set from symptom description |
| L2 analyst | Detects interface and MAC-level anomalies |
| L3 analyst | Identifies routing and ARP issues |
| Consistency checker | Cross-validates L2/L3 state, applies Self-Correction |
| Report generator | Produces structured findings with evidence citations |

- **Multi-vendor by design**: `VENDOR_KEY` decouples the SSH driver (`netmiko_driver`) from the command dictionary — adding a new device type requires only a YAML entry, no code changes.
- **Mock mode**: All agents run against mock data without physical devices, enabling CI/CD-friendly testing.

## 🏁 Getting Started

### Prerequisites

| Tool | Version | Link |
|---|---|---|
| Microsoft Agent Framework | rc5 | `pip install agent-framework` |
| Groq API Key | — | [console.groq.com](https://console.groq.com) |
| Go | 1.21+ | [go.dev](https://go.dev/dl/) |
| Rust + cargo | stable | [rustup.rs](https://rustup.rs) |
| Containerlab | latest | [containerlab.dev](https://containerlab.dev) |

### Setup

1. **Deploy the Topology**:
    ```bash
    sudo containerlab deploy -t infra/containerlab/vpp.clab.yml
    ```

2. **Setup API Key**:
    ```bash
    cp config.ini.example config.ini
    # Edit config.ini and set GROQ_API_KEY
    ```
    Or use the environment variable:
    ```bash
    export SASE_CONFIG=/path/to/config.ini
    ```

3. **Launch Go Control Plane**:
    ```bash
    cd ztna-tetragon-maf/go-control-plane && go run main.go
    ```

4. **Run the MAF Agents**:
    ```bash
    # Security admin agent (Tetragon event monitoring + XDP enforcement)
    python3 ztna-tetragon-maf/python-agents/admin_agent_maf.py

    # User-facing SASE agent (ticket & policy management)
    python3 ztna-tetragon-maf/python-agents/sase_agent_maf.py
    ```

5. **Explore the Notebooks**:
    - [`netmiko-maf/`](./netmiko-maf/) — Network diagnostics and automation with MAF agents
    - [`netconf-rag-maf/`](./netconf-rag-maf/) — NETCONF config generation with RAG + MAF orchestration

## 📄 License

[MIT License](./LICENSE) © 2026 hidemi-k
