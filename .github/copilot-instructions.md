# Hancock AI Agent — Copilot Instructions

This document provides comprehensive guidance for AI coding agents working with the Hancock cybersecurity AI agent repository.

## 🎯 Project Overview

**Hancock** is CyberViser's AI-powered cybersecurity agent, fine-tuned on Mistral 7B, specializing in penetration testing and SOC operations. The agent operates through multiple specialist modes and exposes a REST API for cybersecurity automation.

### Core Capabilities
- **Pentest Specialist**: Reconnaissance, exploitation, CVE analysis, reporting (PTES methodology)
- **SOC Analyst**: Alert triage, SIEM queries, incident response (PICERL framework), threat hunting
- **Code Generation**: Security code (YARA, Sigma, KQL, SPL, Python, Bash)
- **CISO Advisory**: Compliance, risk reporting, board summaries
- **IOC Enrichment**: Threat intelligence for IPs, domains, URLs, hashes, emails

### Technology Stack
- **Language**: Python 3.10+
- **AI Backend**: NVIDIA NIM (Mistral 7B Instruct, Qwen 2.5 Coder 32B)
- **Fine-tuning**: LoRA on Mistral 7B using Unsloth
- **API Framework**: Flask (REST API)
- **Training Data Sources**: MITRE ATT&CK, NVD CVE, CISA KEV, Atomic Red Team, GitHub Security Advisories
- **Deployment**: Docker, Fly.io, Netlify (docs), Hugging Face Spaces

## 🏗️ Architecture

### Directory Structure
```
Hancock/
├── hancock_agent.py          # Main agent (CLI + REST API server)
├── hancock_pipeline.py       # Master data collection pipeline
├── hancock_finetune*.py      # Fine-tuning scripts (GPU/CPU/Cloud)
├── hancock_constants.py      # Shared constants
├── collectors/               # Data collection modules
│   ├── mitre_collector.py    # MITRE ATT&CK TTPs
│   ├── nvd_collector.py      # NVD/CVE vulnerabilities
│   ├── cisa_kev_collector.py # CISA Known Exploited Vulns
│   ├── atomic_collector.py   # Atomic Red Team tests
│   ├── ghsa_collector.py     # GitHub Security Advisories
│   ├── pentest_kb.py         # Pentest knowledge base Q&A
│   └── soc_kb.py            # SOC knowledge base Q&A
├── formatter/               # Training data formatters
│   ├── to_mistral_jsonl.py  # v1 formatter
│   ├── to_mistral_jsonl_v2.py # v2 formatter
│   └── formatter_v3.py      # v3 formatter (all sources)
├── clients/                 # SDK clients
│   ├── python/              # Python SDK + CLI
│   └── nodejs/              # Node.js SDK + CLI
├── tests/                   # Test suite
│   ├── test_hancock_api.py  # API endpoint tests
│   └── test_sdk_client.py   # SDK integration tests
├── data/                    # Training datasets (generated)
├── docs/                    # Documentation + website
├── .github/workflows/       # CI/CD pipelines
└── hancock-cpu-adapter/     # Pre-trained CPU adapter
```

### Key Components

#### 1. Main Agent (`hancock_agent.py`)
- **CLI Mode**: Interactive chat with conversation history
- **Server Mode**: REST API server (port 5000) with 13+ endpoints
- **Personas**: Pentest, SOC, Auto, Code, CISO, Sigma, YARA, IOC
- **Models**: Supports NVIDIA NIM model switching

#### 2. Data Pipeline (`hancock_pipeline.py`)
- **Phase 1**: MITRE ATT&CK + NVD + Pentest KB
- **Phase 2**: + SOC KB (produces hancock_v2.jsonl)
- **Phase 3**: + CISA KEV + Atomic Red Team + GHSA (produces hancock_v3.jsonl)
- **Modes**: `--phase all`, `--phase 3`, `--kb-only` (offline)

#### 3. Fine-tuning Scripts
- **GPU**: `hancock_finetune_gpu.py` (local GPU)
- **Cloud**: `train_modal.py` (Modal.com), `Hancock_Universal_Finetune.ipynb` (Colab/Kaggle)
- **CPU**: `hancock_cpu_finetune.py` (TinyLlama-1.1B, no GPU required)
- **Method**: LoRA adapters using Unsloth + TRL

#### 4. Client SDKs
- **Python SDK**: `clients/python/hancock_client.py` + CLI
- **Node.js SDK**: `clients/nodejs/hancock.js` + CLI
- Both use OpenAI-compatible API interface

## 🛠️ Development Workflows

### Initial Setup
```bash
# Clone and setup environment
git clone https://github.com/cyberviser/Hancock.git
cd Hancock
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and add: NVIDIA_API_KEY="nvapi-..."
```

### Running the Agent
```bash
# Interactive CLI
python hancock_agent.py

# REST API server
python hancock_agent.py --server --port 5000

# With custom model
python hancock_agent.py --model "mistralai/mistral-7b-instruct-v0.3"
```

### Building Training Data
```bash
# Full v3 dataset (requires internet)
python hancock_pipeline.py --phase 3

# Offline mode (KB only)
python hancock_pipeline.py --kb-only

# Skip rate-limited NVD
python hancock_pipeline.py --skip-nvd
```

### Fine-tuning
```bash
# GPU fine-tuning (requires CUDA)
python hancock_finetune_v3.py --steps 300 --export-gguf

# CPU fine-tuning (TinyLlama-1.1B)
python hancock_cpu_finetune.py --debug  # 10 steps test
python hancock_cpu_finetune.py --max-steps 500  # full run

# Cloud fine-tuning (Modal.com)
modal run train_modal.py
```

### Testing
```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test
pytest tests/test_hancock_api.py -v

# Manual API testing
python hancock_agent.py --server &
curl http://localhost:5000/health
```

### Linting
```bash
# Run flake8 (critical errors only)
make lint

# Or directly
flake8 . --count --select=E9,F63,F7,F82 --exclude=.venv,data,docs --show-source --statistics
```

### Docker
```bash
# Build image
docker build -t cyberviser/hancock:latest .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f hancock
```

## 📝 Code Conventions

### Python Style
- **Version**: Python 3.10+
- **Linter**: flake8 (critical errors only: E9, F63, F7, F82)
- **No strict style enforcement**: Use common sense and follow existing patterns
- **Type hints**: Optional but encouraged for public APIs
- **Docstrings**: Required for public functions/classes

### Naming Conventions
- **Files**: `snake_case.py`
- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: `_leading_underscore`

### Error Handling
- Use explicit error messages for user-facing errors
- Log errors with context (timestamps, request IDs for API)
- Fail gracefully with helpful guidance
- Example:
  ```python
  if not api_key:
      print("[Hancock] ❌ NVIDIA_API_KEY not set")
      print("[Hancock] Get one free at: https://build.nvidia.com")
      sys.exit(1)
  ```

### API Design
- Follow REST conventions (GET for reads, POST for writes)
- Return JSON with consistent structure:
  ```json
  {
    "success": true,
    "data": {...},
    "error": null
  }
  ```
- Use HTTP status codes correctly (200, 400, 401, 500)
- Include `/health` and `/metrics` endpoints

### Security Practices
- **Never commit API keys**: Use `.env` files (in `.gitignore`)
- **Validate inputs**: Sanitize user queries before LLM calls
- **Authorization checks**: Always confirm scope for offensive techniques
- **Rate limiting**: Implement for public endpoints
- **HMAC verification**: For webhook endpoints (see `/v1/webhook`)

## 🧪 Testing Strategy

### Test Organization
- **Unit tests**: Test individual collectors, formatters
- **Integration tests**: Test API endpoints (`test_hancock_api.py`)
- **SDK tests**: Test client libraries (`test_sdk_client.py`)
- **Manual tests**: CLI interaction, API curl commands

### Writing Tests
```python
# Follow existing pattern in tests/
import pytest
from hancock_agent import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_endpoint(client):
    response = client.post('/v1/ask', json={'question': 'test'})
    assert response.status_code == 200
    assert 'answer' in response.json
```

### Test Data
- Use small, deterministic samples
- Mock external API calls (MITRE, NVD, etc.)
- Store fixtures in `tests/fixtures/` if needed

## 🚀 CI/CD & Deployment

### GitHub Actions Workflows

#### 1. `python-package-conda.yml`
- **Trigger**: Every push
- **Purpose**: Lint and test with conda environment
- **Steps**: Setup Python 3.10, install deps via conda, run flake8, run pytest

#### 2. `codeql.yml`
- **Trigger**: Push to main, PRs, schedule
- **Purpose**: CodeQL security scanning
- **Languages**: Python

#### 3. `finetune.yml`
- **Trigger**: Manual (workflow_dispatch)
- **Purpose**: Cloud fine-tuning job
- **Platform**: Likely triggers Modal.com or similar

#### 4. `deploy.yml`
- **Trigger**: Push to main (or manual)
- **Purpose**: Deploy to production (Fly.io, Netlify, Spaces)

### Deployment Targets

#### Fly.io (API Server)
```bash
# One-time setup
flyctl launch --config fly.toml

# Deploy updates
flyctl deploy
# or: make fly-deploy
```

#### Netlify (Documentation)
- **Config**: `netlify.toml`
- **Source**: `docs/index.html`
- **Auto-deploy**: Push to main

#### Hugging Face Spaces (Demo)
- **App**: `spaces_app.py`
- **README**: `spaces_README.md`
- **Deploy**: Push to HF repo or use `gradio deploy`

#### Docker Hub
```bash
docker build -t cyberviser/hancock:latest .
docker push cyberviser/hancock:latest
```

## 🔐 Security Considerations

### Ethical Guidelines
- **Authorized scope only**: Agent always confirms authorization before suggesting offensive techniques
- **Responsible disclosure**: Recommend responsible disclosure for vulnerabilities
- **No malicious use**: Do not assist with unauthorized hacking, malware creation, or illegal activities
- **Legal compliance**: All training data from public, legally sourced cybersecurity knowledge bases

### Input Validation
- Sanitize user inputs before passing to LLM
- Limit query length (e.g., max 4000 chars)
- Check for malicious patterns (SQL injection attempts, XSS)

### API Security
- **API Key**: Required via `X-API-Key` header or env var
- **HMAC Signature**: Verify webhook signatures (see `/v1/webhook`)
- **Rate Limiting**: 100 requests/minute per IP (implement in production)
- **CORS**: Configure for frontend integration

### Data Privacy
- **No PII in training data**: Scrub sensitive data from collected datasets
- **No conversation logging**: Don't persist user queries in production
- **Secure storage**: Use encrypted storage for API keys (e.g., Fly.io secrets)

### Vulnerability Management
- **Dependency scanning**: Use `pip-audit` or Dependabot
- **CVE monitoring**: Track vulnerabilities in dependencies
- **Security updates**: Patch critical vulnerabilities within 48 hours
- **Disclosure**: Report security issues to cyberviser@proton.me

## 🤖 AI Agent-Specific Instructions

### When to Use Hancock

#### Perfect Use Cases
1. **Security alert triage**: "Analyze this Splunk alert for potential C2 communication"
2. **Vulnerability analysis**: "Explain CVE-2024-1234 and suggest mitigations"
3. **Detection engineering**: "Write a Sigma rule to detect LSASS memory dumps"
4. **Threat hunting**: "Generate a KQL query to hunt for Kerberoasting"
5. **Incident response**: "Provide a PICERL playbook for ransomware"
6. **Pentest reconnaissance**: "Suggest nmap commands for service enumeration"
7. **CISO reporting**: "Summarize top 5 risks for the board"

#### Not Suitable For
- General programming tasks (use specialized code assistants)
- Non-security infrastructure/DevOps (unless security-related)
- Business logic or frontend development
- General IT support

### Working with the Codebase

#### Adding New Features
1. **New API endpoint**: Add to `hancock_agent.py` following existing pattern
2. **New data source**: Create collector in `collectors/`, update pipeline
3. **New persona**: Add system prompt and mode in `hancock_agent.py`
4. **New SDK method**: Add to both Python and Node.js clients

#### Modifying Training Data
1. Edit the relevant collector in `collectors/`
2. Update formatter if structure changes
3. Regenerate dataset: `python hancock_pipeline.py --phase 3`
4. Fine-tune with new data: `python hancock_finetune_v3.py`

#### Debugging Tips
- **API errors**: Check Flask logs, verify JSON structure
- **LLM errors**: Inspect `response.choices[0].message.content`
- **Training errors**: Check dataset format (JSONL, Mistral instruction format)
- **Collector errors**: Add `--debug` flag, check rate limits

### Code Quality Checklist

Before submitting changes:
- [ ] Code follows existing conventions
- [ ] No API keys or secrets in code
- [ ] Linter passes: `make lint`
- [ ] Tests pass: `make test`
- [ ] Manual testing completed
- [ ] Documentation updated (if API/workflow changed)
- [ ] Commit uses conventional format: `feat:`, `fix:`, `docs:`, `refactor:`

### Common Pitfalls

1. **Rate limits**: NVD API requires key for >10 req/min
2. **Memory usage**: Fine-tuning requires 12GB+ GPU RAM
3. **NVIDIA API key**: Required for inference, get free at build.nvidia.com
4. **Dataset format**: Must be Mistral instruction format (`<s>[INST] ... [/INST] ... </s>`)
5. **Model switching**: Some models require different prompt formats

## 📚 Key Files Reference

### Must-Read Files
1. `README.md` — Project overview, quick start, API reference
2. `CONTRIBUTING.md` — Contribution guidelines
3. `hancock_agent.py` — Main agent implementation
4. `hancock_pipeline.py` — Data collection pipeline
5. `tests/test_hancock_api.py` — API test examples

### Configuration Files
- `.env.example` — Environment variables template
- `requirements.txt` — Python dependencies
- `requirements-dev.txt` — Dev dependencies (pytest, flake8, coverage)
- `pyproject.toml` — Python package metadata
- `Dockerfile` — Docker image definition
- `docker-compose.yml` — Multi-container setup
- `fly.toml` — Fly.io deployment config
- `netlify.toml` — Netlify deployment config
- `Makefile` — Common commands

### Documentation Files
- `BUSINESS_PROPOSAL.md` — Business case and monetization
- `LAUNCH.md` — Launch strategy
- `COMPETITOR_ANALYSIS.md` — Market analysis
- `CHANGELOG.md` — Version history
- `SECURITY.md` — Security policy and disclosure
- `LICENSE` — Proprietary license terms

## 🔄 Continuous Improvement

### Dataset Updates
- **Frequency**: Quarterly or when major CVEs/tactics emerge
- **Process**: Run `python hancock_pipeline.py --phase 3`, review samples, fine-tune
- **Quality**: Manually review 100+ samples before training

### Model Updates
- **Base model**: Monitor Mistral/Meta releases for newer versions
- **Fine-tuning**: Re-train when dataset grows by 20%+ or quality improves
- **Evaluation**: Test on held-out samples, compare to previous version

### API Evolution
- **Versioning**: Use `/v1/` prefix, maintain backward compatibility
- **Deprecation**: 90-day notice for breaking changes
- **Documentation**: Update OpenAPI spec (`docs/openapi.yaml`)

## 🆘 Getting Help

### Internal Resources
- **Issues**: Search existing GitHub issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions
- **Code comments**: Check inline comments in complex functions

### External Resources
- **MITRE ATT&CK**: https://attack.mitre.org
- **NVD/CVE**: https://nvd.nist.gov
- **NVIDIA NIM**: https://build.nvidia.com
- **Unsloth**: https://github.com/unslothai/unsloth
- **Mistral AI**: https://docs.mistral.ai

### Contact
- **Email**: cyberviser@proton.me
- **GitHub**: https://github.com/cyberviser
- **Website**: https://cyberviser.netlify.app

---

## 🎓 Learning Path for New AI Agents

1. **Week 1**: Read README.md, explore `hancock_agent.py`, run CLI mode
2. **Week 2**: Understand data pipeline, run `hancock_pipeline.py --kb-only`
3. **Week 3**: Study API endpoints, test with curl, read test files
4. **Week 4**: Run fine-tuning on Colab, understand LoRA adapters
5. **Week 5**: Contribute: add data samples, improve collectors, write tests

---

**Last Updated**: 2025-03-01
**Maintained By**: CyberViser Team
**Version**: 1.0.0
