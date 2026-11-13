#!/bin/bash
cd "$(dirname "$0")"
echo "Removing macOS Gatekeeper quarantine attributes from GOS LET Bundler..."
xattr -cr .
chmod +x Start_LET_Mac.command
if [ -f "GOS_LET_Bundler" ]; then
    chmod +x GOS_LET_Bundler
fi
echo "✅ Unlocked! You can now double-click Start_LET_Mac.command (or GOS_LET_Bundler)."