# Installation Guide

## Quick Install (Windows)

```powershell
# Clone the repo
git clone https://github.com/your-username/nexus-scanner.git
cd nexus-scanner

# Run the installer
.\install.ps1
```

The installer will:
1. Check Python >= 3.10
2. Check/install Semgrep
3. Install all Python dependencies
4. Create `.env` configuration file
5. Validate the installation

If PowerShell blocks the script, run:
```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

---

## Manual Install (Any OS)

### Prerequisites

| Dependency | Version | Required |
|-----------|---------|----------|
| Python | >= 3.10 | Yes |
| pip | any | Yes |
| Semgrep | >= 1.100 | Optional (for tool verification) |
| Git | any | Optional (for Git diff mode) |

### Step 1: Clone

```bash
git clone https://github.com/your-username/nexus-scanner.git
cd nexus-scanner
```

### Step 2: Create virtual environment (recommended)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Semgrep (optional)

```bash
pip install semgrep
```

Semgrep is used for tool-based verification of LLM hypotheses. Without it, the scanner still works but verification results will show "tool_unavailable".

### Step 5: Configure API key

```bash
cp .env.example .env
```

Edit `.env`:

```ini
NEXUS_API_KEY=your_api_key_here
NEXUS_BASE_URL=https://api.openai.com/v1
NEXUS_MODEL=gpt-4o-mini
```

**Supported providers:**

| Provider | Base URL | Recommended Model |
|----------|----------|-------------------|
| OpenRouter | `https://openrouter.ai/api/v1` | Any |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Xiaomi MiMo | `https://api.xiaomimimo.com/v1` | `mimo-v2.5-pro-max` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |

### Step 6: Verify

```bash
# Run all tests
python -m pytest tests/ -v

# Check CLI
python main_p3.py --help
```

---

## Docker Install

### Build

```bash
docker build -t nexus-scanner .
```

### Run

```bash
docker run --rm \
  -e NEXUS_API_KEY=your_key \
  -e NEXUS_BASE_URL=https://api.openai.com/v1 \
  -v $(pwd)/your-code:/target:ro \
  -v $(pwd)/reports:/app/outputs \
  nexus-scanner \
  --target /target --output /app/outputs/report --vuln-types ALL
```

### Docker Compose

```bash
cp .env.example .env
# Edit .env with your API key

# Run scanner
docker compose up nexus-scanner

# Run dashboard
docker compose up nexus-dashboard
# Open http://localhost:5000
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXUS_API_KEY` | Yes | — | LLM API key |
| `NEXUS_BASE_URL` | No | `https://api.openai.com/v1` | LLM API base URL |
| `NEXUS_MODEL` | No | `gpt-4o-mini` | Model name |
| `NEXUS_NO_EMBEDDING_MODEL` | No | — | Set to `1` to skip sentence-transformers download |

### CLI Arguments

```
python main_p3.py --target <path> [options]

Required:
  --target PATH          Scan target (file or directory)

Options:
  --api-key KEY          API key (or use NEXUS_API_KEY env var)
  --base-url URL         LLM API base URL
  --model MODEL          Model name
  --vuln-types TYPES     Comma-separated, or ALL (default: ALL)
  --output PATH          Report output path (auto-generates .md and .pdf)
  --min-confidence N     Min confidence threshold (default: 0.4)
  --generate-poc         Generate PoC scripts
  --compliance TYPES     Compliance reports (owasp,cwe)
  --diff HEAD~1          Git diff mode — only scan changed files
  --dashboard            Start web dashboard on port 5000
  --incremental          Only scan files changed since last run
  --use-embedding        Enable semantic cache (needs sentence-transformers)
  --langs LANGS          Languages to scan (python,js,go or auto)
  --cost-limit N         Cost limit in USD
  --ci MODE              CI mode (github, gitlab, none)
```

---

## Troubleshooting

### "Python not found"

Install Python from https://www.python.org/downloads/. During setup, check **"Add Python to PATH"**.

### "Semgrep not found"

```bash
pip install semgrep
```

If pip install fails (common on Windows), use:
```bash
pip install semgrep --only-binary=:all:
```

### "No module named 'openai'"

Dependencies not installed. Run:
```bash
pip install -r requirements.txt
```

### "API key not configured"

Edit `.env` and set `NEXUS_API_KEY=your_actual_key`.

### "sentence-transformers download timeout"

The embedding model (~80MB) downloads from HuggingFace on first use. If blocked:
```bash
# Skip model download, use fallback vectorizer
export NEXUS_NO_EMBEDDING_MODEL=1
```

### Permission denied on install.ps1

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# Or run with bypass:
powershell -ExecutionPolicy Bypass -File install.ps1
```

---

## Project Structure

```
nexus-scanner/
├── agents/          # 5 AI agents (Planner, Semantic, Pattern, Verifier, Executor)
├── cache/           # Experience cache (FrugalEngine + EmbeddingCache)
├── cicd/            # CI/CD integration (GitHub Actions, GitLab CI)
├── compliance/      # OWASP Top 10 + CWE mapping
├── core/            # Data structures (FactCard, HypothesisCard, EvidenceChain)
├── cost/            # Token cost tracking
├── dashboard/       # Web dashboard (Flask)
├── exploit/         # PoC generator
├── healing/         # Self-healing layer
├── knowledge/       # Vulnerability pattern library (8 types)
├── languages/       # Multi-language encoders (Python, JS, Go)
├── orchestrator/    # DAG execution engine
├── perception/      # AST-based perception layer
├── policy/          # Policy engine (model routing, budget control)
├── reporting/       # Report generation (Markdown, PDF)
├── storage/         # SQLite persistence
├── tests/           # 151 tests
├── tools/           # Semgrep wrapper
├── vcs/             # Git diff driver
├── main.py          # P0 entry point
├── main_p1.py       # P1 entry point
├── main_p2.py       # P2 entry point
├── main_p3.py       # P3 entry point (primary)
├── install.ps1      # Windows installer
├── Dockerfile       # Docker build
├── docker-compose.yml
├── requirements.txt
├── README.md
└── .env.example
```
