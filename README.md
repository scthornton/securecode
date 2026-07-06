---
license: cc-by-nc-sa-4.0
task_categories:
  - text-generation
  - question-answering
language:
  - en
tags:
  - security
  - cybersecurity
  - ai-security
  - llm-security
  - owasp
  - cve
  - secure-coding
  - vulnerability-detection
  - training-data
  - defense-in-depth
  - prompt-injection
  - ai-ml
  - web-security
size_categories:
  - 1K<n<10K
pretty_name: SecureCode
configs:
  - config_name: default
    data_files:
      - split: train
        path:
          - "data/web/train.parquet"
          - "data/aiml/train.parquet"
  - config_name: web
    data_files:
      - split: train
        path: "data/web/train.parquet"
  - config_name: aiml
    data_files:
      - split: train
        path: "data/aiml/train.parquet"
---

# SecureCode: Comprehensive Security Training Dataset for AI Coding Assistants

<div align="center">

![Examples](https://img.shields.io/badge/examples-2,372-green.svg)
![Languages](https://img.shields.io/badge/languages-12+-orange.svg)
![CWEs](https://img.shields.io/badge/CWEs-92+-blue.svg)
![Frameworks](https://img.shields.io/badge/frameworks-49+-purple.svg)

**The largest open security training dataset for AI coding assistants, covering both traditional web security and AI/ML security**

</div>

---

## Overview

SecureCode combines **2,372 security-focused training examples** into a single, unified dataset with HuggingFace configs for flexible loading. Every example provides vulnerable code, explains why it's dangerous, demonstrates a secure alternative, and includes operational guidance for detection and prevention.

The dataset covers two complementary security domains:

- **Web Security** (1,625 examples): Traditional OWASP Top 10 2021 vulnerabilities across 11 programming languages and 9 web frameworks
- **AI/ML Security** (747 examples): OWASP LLM Top 10 2025 vulnerabilities across 30+ AI/ML frameworks

All conversations are normalized to `{role, content}` format for consistent training.

## Quick Start

```python
from datasets import load_dataset

# Load everything (2,372 examples)
dataset = load_dataset("scthornton/securecode")

# Load only web security examples (1,625)
web = load_dataset("scthornton/securecode", "web")

# Load only AI/ML security examples (747)
aiml = load_dataset("scthornton/securecode", "aiml")
```

## Dataset Configs

| Config | Examples | Focus | OWASP Standard |
|--------|----------|-------|---------------|
| `default` | 2,372 | Everything | Top 10 2021 + LLM Top 10 2025 |
| `web` | 1,625 | Traditional web & application security | OWASP Top 10 2021 |
| `aiml` | 747 | AI/ML system security | OWASP LLM Top 10 2025 |

## SecureCode Dataset Family

This is the **unified** dataset. Individual components are also available as standalone datasets:

| Dataset | Examples | Link |
|---------|----------|------|
| **SecureCode** | 2,372 | This dataset |
| SecureCode Web | 1,625 | [scthornton/securecode-web](https://huggingface.co/datasets/scthornton/securecode-web) |
| SecureCode AI/ML | 747 | [scthornton/securecode-aiml](https://huggingface.co/datasets/scthornton/securecode-aiml) |

## Web Security Coverage (1,625 examples)

### OWASP Top 10 2021 Categories

Counts computed from the `web` config (grouped by `metadata.owasp_2021`).

| Category | Examples |
|----------|----------|
| A03: Injection | 303 |
| A01: Broken Access Control | 303 |
| A07: Identification and Authentication Failures | 234 |
| A02: Cryptographic Failures | 135 |
| A05: Security Misconfiguration | 158 |
| A04: Insecure Design | 138 |
| A06: Vulnerable and Outdated Components | 137 |
| A08: Software and Data Integrity Failures | 99 |
| A09: Security Logging and Monitoring Failures | 66 |
| A10: Server-Side Request Forgery (SSRF) | 52 |

### Languages and Frameworks

JavaScript, Python, Java, Go, PHP, TypeScript, C#, Ruby, Rust, YAML, Kotlin (11 languages) -- covering Express.js, Spring Boot, React, Next.js, FastAPI, GraphQL, SQLAlchemy, Flask, and Vue.

## AI/ML Security Coverage (747 examples)

### OWASP LLM Top 10 2025 Categories

| Category | Code | Examples |
|----------|------|----------|
| Prompt Injection | LLM01 | 75 |
| Sensitive Information Disclosure | LLM02 | 74 |
| Supply Chain Vulnerabilities | LLM03 | 75 |
| Data and Model Poisoning | LLM04 | 75 |
| Improper Output Handling | LLM05 | 75 |
| Excessive Agency | LLM06 | 74 |
| System Prompt Leakage | LLM07 | 74 |
| Vector and Embedding Weaknesses | LLM08 | 75 |
| Misinformation | LLM09 | 75 |
| Unbounded Consumption | LLM10 | 75 |

### Frameworks

LangChain, OpenAI API, Anthropic API, HuggingFace, LlamaIndex, ChromaDB, Pinecone, Qdrant, Weaviate, Milvus, FAISS, vLLM, CrewAI, AutoGen, Dify, Gradio, Streamlit, Chainlit, BentoML, Ray Serve, MLflow, Weights & Biases, Vercel AI SDK, AWS Bedrock, AWS SageMaker, and more.

## Unified Schema

All examples use a normalized conversation format:

```json
{
  "id": "example-id",
  "metadata": {
    "category": "Category name",
    "severity": "CRITICAL",
    "cwe": "CWE-79",
    "lang": "python"
  },
  "context": {
    "description": "Vulnerability description",
    "impact": "Business and technical impact"
  },
  "conversations": [
    {"role": "human", "content": "Developer asks about building a feature"},
    {"role": "assistant", "content": "Vulnerable code + secure code + defense-in-depth"},
    {"role": "human", "content": "Follow-up about testing and edge cases"},
    {"role": "assistant", "content": "Testing guidance + monitoring + common mistakes"}
  ],
  "validation": { ... },
  "quality_score": null,
  "security_assertions": [],
  "references": []
}
```

**Conversation format**: All examples use `{role, content}` (normalized from the original v2.x `{turn, from, value}` format).

**Optional fields**: `quality_score`, `security_assertions`, and `references` are populated for AI/ML examples and null/empty for baseline web examples. Framework-specific web examples include `quality_score` and `security_assertions`.

## Quality

| Metric | Web | AI/ML |
|--------|-----|-------|
| Valid JSON | 1,625/1,625 | 747/747 |
| 4-turn conversations | 100% | 100% |
| Incident grounding | 100% populated (audited; ~69% named incident) | audited: CVEs verified real, fabricated scenario stats corrected |
| Average quality score | N/A (baseline) | 93.8/100 |
| Security assertions | Varies | 5+ per example |

## Usage Examples

### Filter by OWASP Category

```python
# Web: filter by OWASP Top 10 category (web category values are lowercase snake_case;
# filter on owasp_2021 for a stable match)
web = load_dataset("scthornton/securecode", "web")
injection = web["train"].filter(
    lambda x: x.get("metadata", {}).get("owasp_2021", "").startswith("A03")
)

# AI/ML: filter by LLM Top 10 category
aiml = load_dataset("scthornton/securecode", "aiml")
prompt_injection = aiml["train"].filter(
    lambda x: x.get("metadata", {}).get("owasp_llm_2025") == "LLM01"
)
```

### Extract Training Pairs

```python
dataset = load_dataset("scthornton/securecode")

for example in dataset["train"]:
    conversations = example["conversations"]
    for turn in conversations:
        if turn["role"] == "human":
            prompt = turn["content"]
        else:
            response = turn["content"]
```

### Fine-Tuning with Transformers

```python
from datasets import load_dataset
from transformers import AutoTokenizer

dataset = load_dataset("scthornton/securecode")
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-3B")

def format_for_training(example):
    messages = [
        {"role": t["role"].replace("human", "user"), "content": t["content"]}
        for t in example["conversations"]
    ]
    return {"text": tokenizer.apply_chat_template(messages, tokenize=False)}

formatted = dataset["train"].map(format_for_training)
```

## Citation

```bibtex
@misc{thornton2025securecode,
  title={SecureCode: A Production-Grade Multi-Turn Dataset for Training Security-Aware Code Generation Models},
  author={Thornton, Scott},
  year={2026},
  publisher={perfecXion.ai},
  url={https://huggingface.co/datasets/scthornton/securecode},
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

## Ethics and Intended Use

This dataset is **defensive security research**. Every vulnerability example includes a corresponding secure implementation.

**Intended uses:** Training AI coding assistants to write secure code, security education, vulnerability research, security testing preparation.

**Out of scope:** Offensive exploitation, automated attack generation, circumventing security controls.

## License

All 2,372 examples are licensed under **CC BY-NC-SA 4.0**.

## Links

- **SecureCode Web**: [huggingface.co/datasets/scthornton/securecode-web](https://huggingface.co/datasets/scthornton/securecode-web)
- **SecureCode AI/ML**: [huggingface.co/datasets/scthornton/securecode-aiml](https://huggingface.co/datasets/scthornton/securecode-aiml)
- **Research Paper** (v2): [arXiv:2512.18542](https://huggingface.co/papers/2512.18542)
- **Model Collection**: [huggingface.co/collections/scthornton/securecode](https://huggingface.co/collections/scthornton/securecode)
- **Author**: [perfecXion.ai](https://perfecxion.ai)
