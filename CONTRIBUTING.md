# Contributing to Nexus

## Development Setup

```bash
git clone https://github.com/your-username/nexus-scanner.git
cd nexus-scanner
pip install -r requirements.txt
pip install pytest black isort
```

## Workflow

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-vuln-type`
3. Run tests: `pytest tests/ -v`
4. Submit PR with: new vuln type, test samples, recall rate

## Adding a New Vulnerability Type

Each new type MUST include:

- Detection patterns in `knowledge/vuln_patterns.py`
- Detection logic in `perception/encoder.py`
- At least **5 vulnerable samples** + **2 safe samples** (inline code)
- Recall ≥ 80%, False Positive rate ≤ 30%

## Code Style

- Python 3.10+, type annotations on all functions
- Docstring on every module
- `black` for formatting, `isort` for imports
