#!/usr/bin/env bash
# Close R7's LAST gap: boot a real guest from a real restic backup.
#
#   ./tools/verify_boot_live.sh /path/to/some.qcow2
#
# Takes a bootable disk image you already have — any small VM will do —
# backs it up with restic, restores it, boots it under KVM, and watches
# it from outside. Nothing is installed in the guest and no credentials
# are used: the only channels are libvirt's view of the domain and a
# serial console redirected to a file on the host.
#
# If you have no image handy, a tiny one works fine:
#   wget https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img
#   qemu-img convert -O qcow2 cirros-0.6.2-x86_64-disk.img cirros.qcow2
#
# Everything is created under a temp directory and removed at the end.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/.." && pwd)"
PY="$PLATFORM/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

IMAGE="${1:-}"
if [ -z "$IMAGE" ] || [ ! -f "$IMAGE" ]; then
  echo "  usage: $0 /path/to/bootable-disk.qcow2"
  echo
  echo "  Any small bootable qcow2 works. Cirros is ~20MB:"
  echo "    wget https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img"
  echo "    qemu-img convert -O qcow2 cirros-0.6.2-x86_64-disk.img cirros.qcow2"
  exit 2
fi

missing=""
for tool in restic virsh virt-install; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
  echo "  missing:$missing"
  echo
  echo "    sudo apt install restic libvirt-clients virtinst qemu-system-x86"
  echo "    sudo usermod -aG libvirt,kvm \"\$USER\"    # then log out and back in"
  echo
  echo "  A boot test that cannot run is UNVERIFIED, not verified-clean."
  exit 2
fi

echo
echo "  R7 boot verification — real guest, real backup"
echo "  ==================================================================="

WORK="$(mktemp -d)"
PASSFILE="$WORK/password"
echo "r7-boot-verification-throwaway" > "$PASSFILE"
chmod 600 "$PASSFILE"
REPO="$WORK/repo"
SOURCE="$WORK/source"

# Never point at the operator's real backups.
unset RESTIC_REPOSITORY RESTIC_PASSWORD || true
cleanup() {
  virsh --connect qemu:///session destroy ops-verify-live >/dev/null 2>&1 || true
  virsh --connect qemu:///session undefine ops-verify-live >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$SOURCE"
cp "$IMAGE" "$SOURCE/server.qcow2"
echo "  backing up $(basename "$IMAGE") ($(du -h "$IMAGE" | cut -f1))"

restic -r "$REPO" --password-file "$PASSFILE" init >/dev/null
restic -r "$REPO" --password-file "$PASSFILE" backup "$SOURCE" >/dev/null
echo "  snapshot created — now restoring and booting it"
echo

"$PY" "$HERE/verify_boot_live.py" "$REPO" "$PASSFILE"
STATUS=$?

echo
echo "  ==================================================================="
if [ "$STATUS" -eq 0 ]; then
  echo "  R7 BOOT: a machine was restored from backup and came back up."
  echo "  That is proof of recovery — the claim the whole contract exists"
  echo "  to make, now made from observation rather than from design."
else
  echo "  R7 BOOT: did not reach proof of recovery — see above."
  echo "  A real finding, whichever way it went."
fi
echo
exit "$STATUS"
