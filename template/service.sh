#!/system/bin/sh

MODDIR=${0%/*}
STATE_DIR=/data/adb/omk
LOG_DIR=/data/misc/keystore/omk/logs
SERVICE_LOG=$LOG_DIR/service.log

mkdir -p "$STATE_DIR"
# ksud runs this stage with umask(0), so pin the state dir down explicitly:
# it holds the hot-update binaries and the pidfiles.
chown 0:0 "$STATE_DIR"
chmod 0750 "$STATE_DIR"

# Same 4MB ceiling the Rust-side logger rotates at. toybox stat has no
# portable size flag here, so wc -c on the file itself is the safe probe; an
# unreadable log yields an empty count, which is sanitized before comparing.
# The same block decides whether $SERVICE_LOG can be used as the daemons'
# output target: a failed redirection aborts the whole command without forking
# it, so writability is probed once here and start_daemon only redirects when
# the probe succeeded.
LOG_OK=0
if [ -d "$LOG_DIR" ]; then
  size=$(wc -c < "$SERVICE_LOG" 2>/dev/null)
  case "$size" in ''|*[!0-9]*) size=0 ;; esac
  if [ "$size" -gt 4194304 ]; then
    mv -f "$SERVICE_LOG" "$SERVICE_LOG.1" 2>/dev/null
  fi
  if : >> "$SERVICE_LOG" 2>/dev/null; then
    LOG_OK=1
  fi
fi

pid_matches_script() {
  local IFS=' '
  pid=$1
  script=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  # Compare the full argv against the launched path only, the way the baseline
  # grep -F on the whole cmdline did. Matching by basename alone could hit a
  # same-named daemon installed by another module. Globbing stays off while
  # the cmdline is word-split, same as post-fs-data.sh.
  set -f
  for arg in $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null); do
    if [ "$arg" = "$script" ]; then
      set +f
      return 0
    fi
  done
  set +f
  return 1
}

start_daemon() {
  script=$1
  pidfile=$2

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  if [ "$LOG_OK" = 1 ]; then
    sh "$script" >> "$SERVICE_LOG" 2>&1 &
  else
    sh "$script" &
  fi
  pid=$!
  echo "$pid" > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    echo "[omk] failed to start $script" >&2
    return 1
  fi
  return 0
}

start_daemon "$MODDIR/daemon" "$STATE_DIR/keymint-daemon.pid"
start_daemon "$MODDIR/daemon-injector" "$STATE_DIR/injector-daemon.pid"
# Keep the Qualcomm Soter watchdog alive independently of the KeyMint route.
# It owns vendor.qti.hardware.soter.ISoter/default only when its persistent
# software-TA takeover flag requests it; otherwise the stock HAL remains active.
start_daemon "$MODDIR/soterta.sh" "$STATE_DIR/soterta-watchdog.pid"


# Resolve the active root implementation's resetprop binary, with the same
# full fallback chain post-fs-data.sh already uses so both stages agree.
RESETPROP_MODE=direct
RESETPROP_BIN=
for candidate in \
  /data/adb/ksu/bin/resetprop \
  /data/adb/magisk/resetprop \
  /data/adb/ap/bin/resetprop
do
  if [ -x "$candidate" ]; then
    RESETPROP_BIN=$candidate
    break
  fi
done
if [ -z "$RESETPROP_BIN" ] && [ -x /data/adb/ksud ]; then
  RESETPROP_BIN=/data/adb/ksud
  RESETPROP_MODE=ksud
elif [ -z "$RESETPROP_BIN" ] && [ -x /data/adb/apd ]; then
  RESETPROP_BIN=/data/adb/apd
  RESETPROP_MODE=apd
fi
if [ -z "$RESETPROP_BIN" ]; then
  RESETPROP_BIN=$(command -v resetprop 2>/dev/null)
fi
if [ -z "$RESETPROP_BIN" ]; then
  for candidate in /system_ext/bin/resetprop /system/bin/resetprop; do
    if [ -x "$candidate" ]; then
      RESETPROP_BIN=$candidate
      break
    fi
  done
fi

# ksud/apd only speak resetprop through its subcommand, so every read and
# write below goes through this dispatcher instead of the bare binary.
resetprop_exec() {
  if [ "$RESETPROP_MODE" = ksud ] || [ "$RESETPROP_MODE" = apd ]; then
    "$RESETPROP_BIN" resetprop "$@"
  else
    "$RESETPROP_BIN" "$@"
  fi
}

# Despite the name this never creates a missing property: it only overwrites
# a value that is present and differs from EXPECTED.
check_reset_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$(resetprop_exec "$NAME")
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || resetprop_exec "$NAME" "$EXPECTED"
}

# The inverse of check_reset_prop: writes EXPECTED only while the property is
# missing or empty, and never touches an existing (even wrong) value.
check_missing_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$(resetprop_exec "$NAME")
  [ -z "$VALUE" ] && resetprop_exec "$NAME" "$EXPECTED"
}

# The all-rounder its name does not describe: replaces a present-but-wrong
# value AND creates a missing one; only a value already equal to EXPECTED is
# left untouched.
check_missing_match_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$(resetprop_exec "$NAME")
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || resetprop_exec "$NAME" "$EXPECTED"
  [ -z "$VALUE" ] && resetprop_exec "$NAME" "$EXPECTED"
}

# Rewrites the property to NEWVAL only while its current value contains the
# CONTAINS fragment; used to downgrade recovery bootmode traces.
contains_reset_prop() {
  local NAME="$1"
  local CONTAINS="$2"
  local NEWVAL="$3"
  case "$(resetprop_exec "$NAME")" in
    *"$CONTAINS"*) resetprop_exec "$NAME" "$NEWVAL" ;;
  esac
}

# Wait for the framework to come up instead of a fixed sleep: probe
# dev.bootcomplete once per second for at most 30 seconds, then a short
# settle. Past the cap the resets below still run, same as before.
i=0
while [ "$i" -lt 30 ]; do
  [ "$(getprop dev.bootcomplete)" = "1" ] && break
  sleep 1
  i=$((i + 1))
done
sleep 2

if [ -n "$RESETPROP_BIN" ]; then
  # Prop-waiting invocation inherited from PIF. Direct mode keeps the exact
  # "$RESETPROP_BIN -w sys.boot_completed 0" call upstream wrote. ksud/apd
  # only document the resetprop subcommand itself, so -w passthrough is not
  # assured there: poll for the property for up to 30 seconds instead and then
  # write it, tolerating a failure the same way the plain resets below do.
  if [ "$RESETPROP_MODE" = direct ]; then
    resetprop_exec -w sys.boot_completed 0
  else
    j=0
    while [ "$j" -lt 30 ] && [ -z "$(getprop sys.boot_completed)" ]; do
      sleep 1
      j=$((j + 1))
    done
    resetprop_exec sys.boot_completed 0 || true
  fi
  check_missing_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
  check_reset_prop "ro.boot.vbmeta.avb_version" "1.2"
  check_reset_prop "ro.boot.vbmeta.hash_alg" "sha256"
  check_reset_prop "ro.boot.vbmeta.size" "19968"
  check_missing_match_prop "ro.boot.vbmeta.device_state" "locked"
  check_missing_match_prop "ro.boot.verifiedbootstate" "green"
  check_reset_prop "ro.boot.flash.locked" "1"
  check_reset_prop "ro.boot.veritymode" "enforcing"
  check_reset_prop "ro.boot.warranty_bit" "0"
  check_reset_prop "ro.warranty_bit" "0"
  check_reset_prop "ro.debuggable" "0"
  check_reset_prop "ro.force.debuggable" "0"
  check_reset_prop "ro.secure" "1"
  check_reset_prop "ro.adb.secure" "1"
  check_reset_prop "ro.build.type" "user"
  check_reset_prop "ro.build.tags" "release-keys"
  check_reset_prop "ro.vendor.boot.warranty_bit" "0"
  check_reset_prop "ro.vendor.warranty_bit" "0"
  check_missing_match_prop "vendor.boot.vbmeta.device_state" "locked"
  check_missing_match_prop "vendor.boot.verifiedbootstate" "green"
  check_reset_prop "sys.oem_unlock_allowed" "0"
  check_reset_prop "ro.secureboot.lockstate" "locked"
  check_reset_prop "ro.boot.realmebootstate" "green"
  check_reset_prop "ro.boot.realme.lockstate" "1"
  check_reset_prop "ro.crypto.state" "encrypted"

  # Hide adb debugging traces.
  resetprop_exec "sys.usb.adb.disabled" " "
  # Hide recovery boot mode.
  contains_reset_prop "ro.bootmode" "recovery" "unknown"
  contains_reset_prop "ro.boot.bootmode" "recovery" "unknown"
  contains_reset_prop "vendor.boot.bootmode" "recovery" "unknown"
fi

#Hide Lsposed Logd
setprop persist.logd.size ""
setprop persist.logd.size.crash ""
setprop persist.logd.size.system ""
setprop persist.logd.size.main ""

# Hide cloudphone detection.
if [ -n "$RESETPROP_BIN" ] && [ -n "$(resetprop_exec ro.kernel.qemu)" ]; then
  resetprop_exec ro.kernel.qemu ""
fi
