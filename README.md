# Autonomous AI-SASE Framework with eBPF & Multi-Agents

> Autonomous threat detection and response: eBPF monitors the kernel, MAF-powered LLM agents decide the action, Go/Rust enforces it at line rate — no human in the loop.

All AI orchestration is unified on **Microsoft Agent Framework (MAF) rc5**. Tested on MAF rc5; may require changes for GA.

## 📺 Demo

### ZTNA — Autonomous threat blocking (60 sec)
*Coming soon*
<!-- Once recorded, drag-and-drop the .mp4 here and GitHub will embed a player automatically -->

### IPS — Human-in-the-loop enforcement (60 sec)
*Coming soon*
<!-- Once recorded, drag-and-drop the .mp4 here -->

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

Unlike static security tools, this framework was developed through iterative experimentation (documented in the notebooks):

- **Phase 1–5**: Evolution from simple log analysis to reactive policy enforcement.
- **Phase 6**: Task decomposition using DAG (Directed Acyclic Graph) for parallel agent execution.
- **Phase 7 (Current)**: Full Orchestrator-Worker pattern for robust, auditable security operations.

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
│   └── policy.yaml                           # NETCONF operation policy (allowed interfaces, VLANs, forbidden XML ops)
├── netmiko-maf/                              # Network automation via Netmiko + MAF (Jupyter)
│   ├── netmiko_agent_framework.ipynb         # MAF rc5 agent implementation
│   └── network_diagnostic_agent_v5.ipynb     # Diagnostic agent (evolution from v1–v5)
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
MIT License
