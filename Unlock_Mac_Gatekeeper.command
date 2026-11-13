#!/bin/bash
# Resolve the directory containing this script safely in both bash and zsh
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "Removing macOS Gatekeeper quarantine attributes from: $SCRIPT_DIR"
xattr -cr .

if [ -f "Start_LET_Mac.command" ]; then
    chmod +x Start_LET_Mac.command
    echo "✅ Unlocked Start_LET_Mac.command"
fi

if [ -f "GOS_LET_Bundler" ]; then
    chmod +x GOS_LET_Bundler
    echo "✅ Unlocked GOS_LET_Bundler executable"
fi

echo "Done! You can now double-click the application to launch."
