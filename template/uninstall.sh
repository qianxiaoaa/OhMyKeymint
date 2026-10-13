#!/system/bin/sh

# This script only runs on a real uninstall; disabling the module never gets
# here. Keep the cleanup limited to OMK's two persistent roots: disabling a
# module must not remove data.

# Release the Qualcomm Soter service name before removing the module. The
# watchdog restores vendor.soter when disabled; this is best-effort because the
# data tree is removed below even if the service was already gone.
MODDIR=${0%/*}
if [ -x "$MODDIR/soterta.sh" ]; then
  "$MODDIR/soterta.sh" disable >/dev/null 2>&1 || true
fi
pkill -9 -f 'soterta?-svc --mode=' 2>/dev/null || true

# Stop the resident daemons through their pidfiles before the state tree goes
# away, then let init respawn a clean keystore2 without our injection.
for pidfile in \
  /data/adb/omk/keymint-daemon.pid \
  /data/adb/omk/injector-daemon.pid \
  /data/adb/omk/soterta-watchdog.pid
do
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ]; then
      kill -TERM "$pid" 2>/dev/null
      # Give the daemon a bounded window to run its TERM trap before the data
      # tree is removed below: soterta.sh's trap restores the HAL and writes
      # status, both of which still read TA_DIR. Poll the pidfile's process for
      # up to 5 seconds, then continue whether it exited or the wait timed out.
      i=0
      while [ "$i" -lt 5 ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        i=$((i + 1))
      done
    fi
    rm -f "$pidfile"
  fi
done

# pidof may be absent from the shell or may print nothing at all; walking the
# pids one by one keeps kill from ever being called with an empty argument
# list, which would dump its usage message onto stderr.
for p in $(pidof keystore2 2>/dev/null); do
  kill "$p"
done

remove_omk_directory() {
  target="$1"
  case "$target" in
    /data/adb/omk|/data/misc/keystore/omk) ;;
    *)
      echo "[oh_my_keymint] refusing unexpected cleanup path: $target" >&2
      return 1
      ;;
  esac

  if [ -e "$target" ] || [ -L "$target" ]; then
    if ! rm -rf "$target"; then
      echo "[oh_my_keymint] failed to remove $target" >&2
      return 1
    fi
  fi
}

status=0
remove_omk_directory /data/adb/omk || status=1
remove_omk_directory /data/misc/keystore/omk || status=1
exit "$status"
