#!/usr/bin/env bash
# PreToolUse hook for Edit|Write|MultiEdit.
# Blocks automated edits to guarded paths so the agent can't loosen its own
# guardrails mid-pipeline. Claude Code passes the tool call as JSON on stdin;
# we extract tool_input.file_path and match it against the guard list.
#
# Exit 2 = block (stderr is surfaced to the model as the reason).
# Design choice: fail CLOSED — if we cannot identify the target but the raw
# payload mentions a guarded path, block rather than risk a silent bypass.

set -euo pipefail

payload="$(cat)"

is_guarded() {
  # $1 already normalized to forward slashes.
  case "$1" in
    */.github/workflows/*|*/CLAUDE.md|CLAUDE.md|*/.claude/*|.claude/*) return 0 ;;
    *) return 1 ;;
  esac
}

# Regex-extract the file_path value from the JSON (no parser dependency; works
# for forward-slash and escaped-backslash Windows paths alike).
FILE="$(printf '%s' "$payload" \
  | grep -oE '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | head -1 \
  | sed -E 's/.*"file_path"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"

# Normalize: strip CR, collapse any backslashes to forward slashes.
FILE="$(printf '%s' "$FILE" | tr -d '\r\n')"
FILE="${FILE//\\//}"

if [ -n "$FILE" ]; then
  if is_guarded "$FILE"; then
    echo "Blocked: '$FILE' is a guarded path (.github/workflows, CLAUDE.md, or .claude/). Edit it manually, not via an automated tool call." >&2
    exit 2
  fi
  exit 0
fi

# Could not extract a file_path. Fail closed if the raw payload references a
# guarded path anywhere; otherwise allow (nothing identifiable to protect).
norm_payload="${payload//\\//}"
case "$norm_payload" in
  */.github/workflows/*|*/CLAUDE.md|*/.claude/*)
    echo "Blocked: could not parse file_path but payload references a guarded path; refusing to risk a bypass." >&2
    exit 2
    ;;
esac
exit 0
