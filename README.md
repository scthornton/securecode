# SecureCode

**Comprehensive security training dataset for AI coding assistants — 2,185 examples covering both traditional web security and AI/ML security.**

Built by [perfecXion.ai](https://perfecxion.ai).

## Dataset Family

| Dataset | Examples | Focus | HuggingFace | GitHub |
|---------|----------|-------|-------------|--------|
| **SecureCode** | 2,185 | Unified (web + AI/ML) | [scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode) | This repo |
| SecureCode v2 | 1,435 | Web security (OWASP Top 10 2021) | [scthornton/securecode-v2](https://huggingface.co/datasets/scthornton/securecode-v2) | [securecode-v2](https://github.com/scthornton/securecode-v2) |
| SecureCode AI/ML | 750 | AI/ML security (OWASP LLM Top 10 2025) | [scthornton/securecode-aiml](https://huggingface.co/datasets/scthornton/securecode-aiml) | [securecode-aiml](https://github.com/scthornton/securecode-aiml) |

## Quick Start

```python
from datasets import load_dataset

# Load everything (2,185 examples)
dataset = load_dataset("scthornton/securecode")

# Load only web security (1,435 examples)
web = load_dataset("scthornton/securecode", "web")

# Load only AI/ML security (750 examples)
aiml = load_dataset("scthornton/securecode", "aiml")
```

## What's In It

Every example is a 4-turn conversation between a developer and an AI coding assistant. The developer asks how to build something, and the assistant provides a vulnerable implementation, explains why it's dangerous, shows a secure alternative with 5+ defense layers, and then covers testing, monitoring, and common mistakes.

**Web Security (1,435 examples):** SQL injection, XSS, authentication bypass, SSRF, cryptographic failures, and more across 12 programming languages and 9 web frameworks (Express.js, Django, Spring Boot, Flask, Rails, Laravel, ASP.NET Core, FastAPI, NestJS).

**AI/ML Security (750 examples):** Prompt injection, model poisoning, embedding manipulation, system prompt leakage, excessive agent autonomy, and more across 30+ AI/ML frameworks (LangChain, OpenAI, Anthropic, HuggingFace, LlamaIndex, ChromaDB, vLLM, CrewAI, AutoGen, etc.).

## Unified Schema

All conversations use a normalized `{role, content}` format:

```json
{
  "id": "example-id",
  "metadata": { "category": "...", "severity": "CRITICAL", "cwe": "CWE-79", "lang": "python" },
  "context": { "description": "...", "impact": "..." },
  "conversations": [
    {"role": "human", "content": "How do I build secure JWT auth?"},
    {"role": "assistant", "content": "Here's the vulnerable version... here's the secure version..."},
    {"role": "human", "content": "How do I test this?"},
    {"role": "assistant", "content": "Here's how to test, monitor, and avoid common mistakes..."}
  ],
  "quality_score": null,
  "security_assertions": [],
  "references": []
}
```

## Building the Unified Dataset

The unified dataset is built from the two source datasets using a normalization script that converts v2.x conversations from `{turn, from, value}` to `{role, content}` format.

```bash
python3 scripts/build_unified_dataset.py
```

This generates `unified-data/data/web/` (1,435 files) and `unified-data/data/aiml/` (750 files), ready to push to HuggingFace.

## Configs

| Config | Examples | OWASP Standard |
|--------|----------|----------------|
| `default` | 2,185 | Both |
| `web` | 1,435 | OWASP Top 10 2021 |
| `aiml` | 750 | OWASP LLM Top 10 2025 |

## Citation

```bibtex
@misc{thornton2025securecode,
  title={SecureCode v2.0: A Production-Grade Dataset for Training Security-Aware Code Generation Models},
  author={Thornton, Scott},
  year={2025},
  publisher={perfecXion.ai},
  url={https://huggingface.co/datasets/scthornton/securecode-v2},
  note={arXiv:2512.18542}
}

@dataset{thornton2026securecodeaiml,
  title={SecureCode AI/ML: AI/ML Security Training Dataset for the OWASP LLM Top 10 2025},
  author={Thornton, Scott},
  year={2026},
  publisher={perfecXion.ai},
  url={https://huggingface.co/datasets/scthornton/securecode-aiml}
}
```

## License

- **Web examples:** CC BY-NC-SA 4.0
- **AI/ML examples:** MIT
- **Unified dataset:** CC BY-NC-SA 4.0 (the more restrictive of the two)
