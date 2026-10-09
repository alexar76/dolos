#!/usr/bin/env bash
# Install the periodic DOLOS scan on a host that already has the UNI anvil, Foundry and the
# contract `out/` ABIs — in practice the box running the UNI Alien Monitor.
#
# It does NOT deploy DOLOS as a service: DOLOS has no daemon and listens on nothing. What this
# installs is a TIMER that runs one scan cycle and exits.
#
#   sudo ./install-timer.sh [--user dolos] [--interval hourly] [--dry-run]
set -euo pipefail

RUN_AS="${DOLOS_RUN_AS:-root}"
CALENDAR="${DOLOS_ONCALENDAR:-hourly}"
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --user) RUN_AS="$2"; shift 2 ;;
    --interval) CALENDAR="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR=/etc/systemd/system

# Fail closed on the two things that make a cycle impossible, rather than installing a timer that
# will fail silently every hour.
command -v anvil >/dev/null || { echo "anvil not found — DOLOS needs Foundry to fork" >&2; exit 1; }
command -v forge >/dev/null || { echo "forge not found — DOLOS needs Foundry" >&2; exit 1; }

echo "installing:"
echo "  run as     : ${RUN_AS}"
echo "  schedule   : ${CALENDAR}"
echo "  units      : ${UNIT_DIR}/dolos-scan.{service,timer}"
[ "$DRY" = 1 ] && { echo "(dry run — nothing written)"; exit 0; }

install -m 0644 "${HERE}/dolos-scan.service" "${UNIT_DIR}/dolos-scan.service"
sed "s|^OnCalendar=.*|OnCalendar=${CALENDAR}|" "${HERE}/dolos-scan.timer" \
  > "${UNIT_DIR}/dolos-scan.timer"
# %i is only substituted for templated units, so the concrete user is patched in here.
sed -i "s|^User=%i$|User=${RUN_AS}|" "${UNIT_DIR}/dolos-scan.service"

install -d -m 0750 /var/lib/dolos
systemctl daemon-reload
systemctl enable --now dolos-scan.timer

echo
echo "done. Verify with:"
echo "  systemctl list-timers dolos-scan.timer"
echo "  systemctl start dolos-scan.service   # force one cycle now"
echo "  journalctl -u dolos-scan.service -n 40"
