#!/usr/bin/env python3
"""Build the unified SecureCode dataset from v2.x and AI/ML sources.

Normalizes all examples to {role, content} conversation format and
organizes into web/ and aiml/ subdirectories for HuggingFace configs.

Usage:
    python3 scripts/utilities/build_unified_dataset.py

Output:
    unified-data/
    ├── web/     (1,435 normalized JSONL files)
    └── aiml/    (750 JSONL files, copied as-is)
"""

import json
import shutil
import sys
from pathlib import Path

# Paths
V2_BASELINE = Path("/Users/scott/perfecxion/securecode2-source/data")
V2_ADDITIONS = Path("/Users/scott/perfecxion/securecode3/generation/outputs/v2-1-production-ready")
V3_AIML = Path("/Users/scott/perfecxion/securecode3/data")
OUTPUT = Path("/Users/scott/perfecxion/securecode3/unified-data")


def normalize_conversation(conv_turn: dict) -> dict:
    """Convert {turn, from, value} to {role, content}."""
    return {
        "role": conv_turn.get("from", conv_turn.get("role", "unknown")),
        "content": conv_turn.get("value", conv_turn.get("content", "")),
    }


def normalize_example(example: dict) -> dict:
    """Normalize a v2.x example to unified schema."""
    normalized = dict(example)

    # Normalize conversations
    if "conversations" in normalized:
        normalized["conversations"] = [
            normalize_conversation(turn) for turn in normalized["conversations"]
        ]

    # Add missing fields with defaults
    if "quality_score" not in normalized:
        normalized["quality_score"] = None
    if "security_assertions" not in normalized:
        normalized["security_assertions"] = []
    if "references" not in normalized:
        normalized["references"] = []

    return normalized


def process_v2_baseline(output_dir: Path) -> int:
    """Process v2.0 baseline files (multi-line JSONL)."""
    count = 0
    file_idx = 0
    for jsonl_path in sorted(V2_BASELINE.glob("*.jsonl")):
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    example = json.loads(line)
                    normalized = normalize_example(example)
                    # Write each example as a separate JSONL file
                    example_id = normalized.get("id", f"v2-baseline-{file_idx:06d}")
                    safe_id = example_id.replace("/", "_").replace(" ", "_")
                    out_path = output_dir / f"{safe_id}.jsonl"
                    # Handle duplicate filenames
                    if out_path.exists():
                        out_path = output_dir / f"{safe_id}_{file_idx:06d}.jsonl"
                    with open(out_path, "w") as out:
                        json.dump(normalized, out, ensure_ascii=False)
                        out.write("\n")
                    count += 1
                    file_idx += 1
                except json.JSONDecodeError as e:
                    print(f"  WARN: JSON error in {jsonl_path.name}: {e}", file=sys.stderr)
    return count


def process_v2_additions(output_dir: Path) -> int:
    """Process v2.1 addition files (single-JSON JSONL)."""
    count = 0
    for jsonl_path in sorted(V2_ADDITIONS.glob("*.jsonl")):
        with open(jsonl_path) as f:
            try:
                example = json.load(f)
                normalized = normalize_example(example)
                example_id = normalized.get("id", jsonl_path.stem)
                safe_id = example_id.replace("/", "_").replace(" ", "_")
                out_path = output_dir / f"{safe_id}.jsonl"
                if out_path.exists():
                    out_path = output_dir / f"{safe_id}_v21.jsonl"
                with open(out_path, "w") as out:
                    json.dump(normalized, out, ensure_ascii=False)
                    out.write("\n")
                count += 1
            except json.JSONDecodeError as e:
                print(f"  WARN: JSON error in {jsonl_path.name}: {e}", file=sys.stderr)
    return count


def process_aiml(output_dir: Path) -> int:
    """Copy v3.0 AI/ML files as-is (already in {role, content} format)."""
    count = 0
    for jsonl_path in sorted(V3_AIML.glob("*.jsonl")):
        shutil.copy2(jsonl_path, output_dir / jsonl_path.name)
        count += 1
    return count


def validate_conversations(data_dir: Path, label: str) -> tuple[int, int]:
    """Validate all files use {role, content} format."""
    ok = 0
    bad = 0
    for jsonl_path in sorted(data_dir.glob("*.jsonl")):
        with open(jsonl_path) as f:
            content = f.read().strip()
        if not content:
            continue
        try:
            example = json.loads(content)
            if not isinstance(example, dict):
                print(f"  BAD: {jsonl_path.name} is not a dict (type={type(example).__name__})")
                bad += 1
                continue
            convs = example.get("conversations", [])
            if isinstance(convs, str):
                convs = json.loads(convs)
            for turn in convs:
                if isinstance(turn, str):
                    turn = json.loads(turn)
                if "role" not in turn or "content" not in turn:
                    print(f"  BAD: {jsonl_path.name} has non-normalized turn: {list(turn.keys())}")
                    bad += 1
                    break
            else:
                ok += 1
        except json.JSONDecodeError as e:
            print(f"  BAD: {jsonl_path.name} JSON error: {e}")
            bad += 1
    return ok, bad


def main():
    print("=" * 60)
    print("Building Unified SecureCode Dataset")
    print("=" * 60)

    # Create output directories
    web_dir = OUTPUT / "data" / "web"
    aiml_dir = OUTPUT / "data" / "aiml"
    web_dir.mkdir(parents=True, exist_ok=True)
    aiml_dir.mkdir(parents=True, exist_ok=True)

    # Process web data
    print("\n[1/3] Processing v2.0 baseline...")
    baseline_count = process_v2_baseline(web_dir)
    print(f"  Normalized {baseline_count} baseline examples")

    print("\n[2/3] Processing v2.1 additions...")
    additions_count = process_v2_additions(web_dir)
    print(f"  Normalized {additions_count} framework addition examples")

    web_total = baseline_count + additions_count
    print(f"\n  Web total: {web_total} examples")

    # Process AI/ML data
    print("\n[3/3] Copying AI/ML examples...")
    aiml_count = process_aiml(aiml_dir)
    print(f"  Copied {aiml_count} AI/ML examples")

    # Validate
    print("\n" + "=" * 60)
    print("Validation")
    print("=" * 60)

    print("\nValidating web data...")
    web_ok, web_bad = validate_conversations(web_dir, "web")
    print(f"  OK: {web_ok}, BAD: {web_bad}")

    print("\nValidating AI/ML data...")
    aiml_ok, aiml_bad = validate_conversations(aiml_dir, "aiml")
    print(f"  OK: {aiml_ok}, BAD: {aiml_bad}")

    # Summary
    total = web_total + aiml_count
    total_bad = web_bad + aiml_bad
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Web examples:  {web_total}")
    print(f"  AI/ML examples: {aiml_count}")
    print(f"  Total:          {total}")
    print(f"  Validation errors: {total_bad}")
    print(f"\n  Output: {OUTPUT}")

    if total_bad > 0:
        print("\nWARNING: Some examples failed validation!")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
