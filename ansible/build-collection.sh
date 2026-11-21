#!/usr/bin/env bash
# Build the abbasi26.certclock Ansible collection into dist/.
# Copies the bundled collector files so the collection and the Python package ship the same files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
coll="$root/ansible/collection"
mkdir -p "$coll/playbooks" "$root/dist"
cp "$root/src/certclock/bundled/certclock-linux.yml" "$coll/playbooks/certclock_linux.yml"
cp "$root/src/certclock/bundled/collect_linux_certs.py" "$coll/playbooks/collect_linux_certs.py"
cp "$root/LICENSE" "$coll/LICENSE"
ansible-galaxy collection build "$coll" --output-path "$root/dist" --force
