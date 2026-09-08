#!/usr/bin/env python3
"""Export an auditable Claude Code action transcript without private reasoning.

The source is Claude Code's session JSONL. The output retains user prompts,
assistant-visible text, tool calls, and tool results in order. Thinking blocks,
host-specific metadata, billing data, and unrelated attachments are omitted.
"""

import argparse
import json
from pathlib import Path


def clean_content(content, episode: str):
    def redact(value: str) -> str:
        return value.replace(episode, "$EPISODE_ROOT").replace("/home/chetan", "$HOME")

    if isinstance(content, str):
        return redact(content)
    cleaned = []
    for block in content or []:
        if not isinstance(block, dict) or block.get("type") == "thinking":
            continue
        block = json.loads(redact(json.dumps(block)))
        cleaned.append(block)
    return cleaned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--episode-root", required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.source.open() as src, args.output.open("w") as dst:
        for line in src:
            record = json.loads(line)
            if record.get("type") not in {"user", "assistant"}:
                continue
            message = record.get("message")
            if not isinstance(message, dict):
                continue
            out = {
                "timestamp": record.get("timestamp"),
                "role": message.get("role"),
                "content": clean_content(message.get("content"), args.episode_root),
            }
            dst.write(json.dumps(out, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
