#!/usr/bin/env bash
# PreToolUse hook for POSIX shells
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$DIR/deny_dangerous.py" "$@"
