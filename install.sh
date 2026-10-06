#!/usr/bin/env bash
# Seeker v2 needs nothing but Python 3.8+. This script only verifies that.
set -u

MIN_MAJOR=3
MIN_MINOR=8

echo '[!] Checking dependencies...'

if ! command -v python3 >/dev/null 2>&1; then
  echo '[-] python3 is not installed.'
  echo '    Debian/Ubuntu : sudo apt install python3'
  echo '    Fedora        : sudo dnf install python3'
  echo '    Arch          : sudo pacman -S python'
  echo '    Termux        : pkg install python'
  exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)')

if [ "$PY_OK" != "1" ]; then
  echo "[-] Python $PY_VERSION found, but 3.8+ is required."
  exit 1
fi

echo "[+] python3 $PY_VERSION - ok"
echo '[+] No PHP, no pip packages, no build step required.'
echo
echo '[!] Running environment checks...'
python3 seeker.py doctor || exit 1

echo
echo '[+] Ready. Start the console with:'
echo '      python3 seeker.py serve'
