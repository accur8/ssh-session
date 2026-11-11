#!/usr/bin/env bash
# Install ssh-session for this account, on macOS or Linux (WSL included). Needs nix.
#
#   curl -fsSL https://raw.githubusercontent.com/accur8/ssh-session/main/install.sh | bash
#   bash install.sh [TAG]        # TAG defaults to the release below
#
# What it does, and it is safe to run again:
#   1. builds the release into a pinned link, ~/.local/state/ssh-session/tool
#   2. links ~/bin/ssh-session to it
#   3. removes ~/bin/gitkey when it is a link (the old command; it is now
#      `ssh-session gitkey load` and `ssh-session gitkey enroll`)
#   4. says what this machine has: PATH, the ssh-agent, the keys, who would sign
# It never touches a key, the agent's contents, or anything it did not link.
set -euo pipefail

TAG=${1:-v1.0.5}
TOOL="$HOME/.local/state/ssh-session/tool"
BIN="$HOME/bin"
say() { printf '%s\n' "$*"; }

command -v nix >/dev/null 2>&1 || { say "ssh-session install: nix is not on the PATH; install nix first"; exit 1; }

say "building github:accur8/ssh-session/$TAG"
mkdir -p "$(dirname "$TOOL")" "$BIN"
nix --extra-experimental-features 'nix-command flakes' build "github:accur8/ssh-session/$TAG" --out-link "$TOOL"
[ -x "$TOOL/bin/ssh-session" ] || { say "ssh-session install: the build has no bin/ssh-session"; exit 1; }

# ~/bin/ssh-session: replace a link (the old tier0 one included); never a real file.
if [ -e "$BIN/ssh-session" ] && [ ! -L "$BIN/ssh-session" ]; then
  say "ssh-session install: $BIN/ssh-session is a file, not a link; move it away and run this again"
  exit 1
fi
ln -sfn "$TOOL/bin/ssh-session" "$BIN/ssh-session"
say "linked $BIN/ssh-session -> $TOOL/bin/ssh-session"

if [ -L "$BIN/gitkey" ]; then
  rm "$BIN/gitkey"
  say "removed the old $BIN/gitkey link (now: ssh-session gitkey load)"
fi

say ""
say "this machine:"
case ":$PATH:" in
  *":$BIN:"*) say "  PATH       $BIN is on it" ;;
  *) say "  PATH       $BIN is NOT on it: add it in your shell's startup file, then open a new shell" ;;
esac
if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "$SSH_AUTH_SOCK" ]; then
  say "  ssh-agent  running"
else
  say "  ssh-agent  none in this shell: start one (eval \"\$(ssh-agent -s)\") before ssh-session"
fi
key=""; for k in id_ed25519 id_ecdsa id_rsa; do [ -f "$HOME/.ssh/$k" ] && [ -f "$HOME/.ssh/$k.pub" ] && { key=$k; break; }; done
[ -n "$key" ] && say "  key        ~/.ssh/$key (certified by the account CA when no YubiKey signs)" || say "  key        none of ~/.ssh/id_ed25519, id_ecdsa, id_rsa"
if [ -f "$HOME/.ssh/id_ed25519_git" ]; then
  say "  git key    ~/.ssh/id_ed25519_git is here"
elif [ "$(uname -s)" = Darwin ]; then
  say "  git key    none: make it once with: ssh-session gitkey enroll"
else
  say "  git key    none (its passphrase store is the macOS Keychain; not available here)"
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  say "  WSL        a YubiKey is visible here only after it is attached from Windows (usbipd)"
fi

say ""
say "ssh-session status:"
"$TOOL/bin/ssh-session" status | sed 's/^/  /'
say ""
say "next:  ssh-session          # today's session, and the git key"
