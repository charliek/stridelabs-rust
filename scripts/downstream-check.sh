#!/usr/bin/env bash
# Build and test a CONSUMER of stridelabs-rust against THIS checkout of the
# library: the local gate that runs before a library change is tagged.
#
#   scripts/downstream-check.sh [--dry-run] <consumer[,consumer...]|all> <ref> [extra cargo flags]
#
# consumer  tapper | slauth | limen | spendwise   (limen is also checked in CI,
#           by the `downstream-limen` job; the other three are private repos
#           whose test output must not land in a public Actions log, so they
#           are checked only here)
# ref       any ref the consumer's repo resolves (branch, tag, SHA, origin/main).
#           With several consumers the same ref is looked up in each repo;
#           DOWNSTREAM_<NAME>_REF overrides it for one of them.
# extra     appended to BOTH the clippy and the test invocation, e.g.
#           `--features foo` or `--no-default-features`.
#
# How it works, and why it is not `cargo test` in the consumer's checkout:
#   - The consumer ref is `git archive`d into $WORK/<consumer>, a fresh
#     directory every run. No worktree metadata, and the consumer's real repo
#     and Cargo.lock are never touched.
#   - All five stridelabs-* crates are overridden with `--config
#     'patch."<git url>".<crate>.path=...'` pointing at this checkout. [patch]
#     is keyed by the source URL, so it applies to a consumer that pins by
#     `tag` and to one that pins by `rev` alike.
#   - The run is NOT --locked: the scratch copy's lock is re-resolved so the
#     patched path packages (and anything new they pull in) can enter it. That
#     makes this a DEVELOPMENT check. The binding proof builds each consumer
#     from its own committed rev pin and Cargo.lock with --locked.
#   - Every build uses CARGO_TARGET_DIR=$SCRATCH/target-<consumer>.
#
# Exit status: 0 when every REQUIRED consumer (tapper, slauth, limen) passed;
# 1 when one failed, or when the run changed the library tree; 2 when it
# refused to start (usage, dirty library tree, missing env or service).
# spendwise is INFORMATIONAL: its result is printed but never decides the exit.
#
# Environment (names only; this script never prints a value):
#   tapper     TAPPER_RS_TEST_DATABASE_URL  a MIGRATED Postgres that is not the dev stack's
#              TAPPER_RS_TEST_REDIS_URL     a Redis DB number other than 0
#              and fake-gcs-server on localhost:4443 (`docker compose up -d fake-gcs-server`).
#              There is no default for either variable, on purpose: tapper's
#              own tests fail rather than skip without them, and a default
#              would be the dev database. See "tapper-rs" in tapper's CLAUDE.md.
#   slauth     a Postgres superuser. Tests use their own default (the repo's
#              docker compose, localhost:5433) unless DOWNSTREAM_SLAUTH_DATABASE_URL
#              is set; the ambient DATABASE_URL is never inherited. The
#              adoption tests also run `uv run alembic` in the archived
#              backend/, so `uv` and its private-index setup must work in
#              this shell.
#   spendwise  a Postgres, the same way (default localhost:5437, override
#              DOWNSTREAM_SPENDWISE_DATABASE_URL). This script does not
#              provision it.
#   limen      nothing.
#   DOWNSTREAM_<NAME>_REPO overrides a consumer's repo path. DOWNSTREAM_LIB
#   overrides the library path (default: the checkout this script is in),
#   DOWNSTREAM_SCRATCH the scratch root, DOWNSTREAM_LOCK_TIMEOUT the seconds
#   to wait for the lock (default 3600).
#
# Written for bash 3.2 (macOS /bin/bash) as well as current bash.

set -uo pipefail

LIB=${DOWNSTREAM_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SCRATCH=${DOWNSTREAM_SCRATCH:-/Volumes/miniext/scratch-011}
WORK=$SCRATCH/downstream
LOGS=$WORK/logs
LOCK=$WORK/.lock
LIB_URL='https://github.com/charliek/stridelabs-rust.git'
CRATES='config observability http auth testing'
KNOWN_CONSUMERS='tapper slauth limen spendwise'

usage() {
  cat >&2 <<'EOF'
usage: scripts/downstream-check.sh [--dry-run] <consumer[,consumer...]|all> <ref> [extra cargo flags]
  consumer: tapper | slauth | limen | spendwise (spendwise is informational)
  --dry-run: run every check, print the plan, build nothing
See the header of this script for the environment each consumer needs.
EOF
}

die() {
  printf 'downstream-check: %s\n' "$*" >&2
  exit 2
}

# ---------------------------------------------------------------- arguments

DRY_RUN=0
while [ $# -gt 0 ]; do
  case $1 in
    -n | --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage
      die "unknown option: $1"
      ;;
    *) break ;;
  esac
done
[ $# -ge 2 ] || {
  usage
  die "need <consumer> and <ref>"
}
CONSUMERS_ARG=$1
REF_ARG=$2
shift 2
EXTRA=("$@")

if [ "$CONSUMERS_ARG" = all ]; then
  CONSUMERS_ARG=${KNOWN_CONSUMERS// /,}
fi
IFS=, read -r -a CONSUMERS <<<"$CONSUMERS_ARG"
[ "${#CONSUMERS[@]}" -gt 0 ] || die "no consumer given"
for c in "${CONSUMERS[@]}"; do
  case " $KNOWN_CONSUMERS " in
    *" $c "*) ;;
    *)
      usage
      die "unknown consumer '$c' (known: $KNOWN_CONSUMERS)"
      ;;
  esac
done

# ------------------------------------------------------------ consumer table

# Sets C_* for one consumer. The clippy and test flags are the ones that
# consumer's own CI uses, minus --locked (see the header): tapper-rs runs
# clippy with --all-features (its CI job tapper-rs-check), limen and spendwise
# test with --all, slauth with plain `cargo test`. The command line's extra
# flags are appended to both.
load_consumer() {
  local var
  C_NAME=$1
  C_UPPER=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
  C_TEST_FLAGS=()
  case $1 in
    tapper)
      C_REPO=/Volumes/miniext/projects/tapper
      C_CRATE=tapper-rs
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets --all-features)
      ;;
    slauth)
      C_REPO=/Users/charliek/projects/slauth
      C_CRATE=backend-rs
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets)
      ;;
    limen)
      C_REPO=/Users/charliek/projects/limen
      C_CRATE=.
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets)
      C_TEST_FLAGS=(--all)
      ;;
    spendwise)
      C_REPO=/Users/charliek/projects/spendwise-rs
      C_CRATE=backend
      C_KIND=informational
      C_CLIPPY_FLAGS=(--all-targets)
      C_TEST_FLAGS=(--all)
      ;;
  esac
  C_CLIPPY_FLAGS+=(${EXTRA[@]+"${EXTRA[@]}"})
  C_TEST_FLAGS+=(${EXTRA[@]+"${EXTRA[@]}"})
  var=DOWNSTREAM_${C_UPPER}_REPO
  C_REPO=${!var:-$C_REPO}
  var=DOWNSTREAM_${C_UPPER}_REF
  C_REF=${!var:-$REF_ARG}
  var=DOWNSTREAM_${C_UPPER}_DATABASE_URL
  C_DB_URL=${!var:-}
  C_DIR=$WORK/$C_NAME
  C_CRATE_DIR=$C_DIR/$C_CRATE
  # Empty when the ref does not resolve: preflight reports that.
  C_SHA=$(git -C "$C_REPO" rev-parse --verify --quiet "$C_REF^{commit}" 2>/dev/null)
}

# ----------------------------------------------------------------- helpers

PROBLEMS=()
problem() { PROBLEMS+=("$*"); }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || problem "'$1' is not on PATH"
}

# The database number a redis:// URL selects; 0 when it names none.
redis_db() {
  local u=${1#*://}
  case $u in
    */*)
      u=${u#*/}
      u=${u%%\?*}
      printf '%s' "${u:-0}"
      ;;
    *) printf 0 ;;
  esac
}

tcp_open() { # host port
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 3 "$1" "$2" >/dev/null 2>&1
  else
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null
  fi
}

need_tcp() { # label host port hint
  tcp_open "$2" "$3" || problem "$1 is not reachable at $2:$3 ($4)"
}

# need_tcp on the host and port a URL names, without its credentials: the value
# is never echoed.
need_url_tcp() { # label url default-port hint
  local a=${2#*://}
  a=${a%%[/?]*}
  a=${a##*@}
  case $a in
    *:*) need_tcp "$1" "${a%%:*}" "${a##*:}" "$4" ;;
    *) need_tcp "$1" "$a" "$3" "$4" ;;
  esac
}

need_env() { # variable description
  [ -n "${!1:-}" ] || problem "$1 is not set ($2)"
}

# Postgres for slauth and spendwise: the override URL when given, else the
# port the consumer's own tests default to. Sets nothing; only checks.
need_default_postgres() { # default-port compose-hint
  if [ -n "$C_DB_URL" ]; then
    need_url_tcp "the $C_NAME test Postgres" "$C_DB_URL" 5432 "$2"
  else
    need_tcp "the $C_NAME test Postgres" localhost "$1" "$2"
  fi
}

# Everything a consumer needs before a build is worth starting. Fills PROBLEMS.
preflight() {
  PROBLEMS=()
  [ -d "$C_REPO/.git" ] || [ -f "$C_REPO/.git" ] || problem "$C_REPO is not a git repository (set DOWNSTREAM_${C_UPPER}_REPO)"
  [ -n "$C_SHA" ] || problem "ref '$C_REF' does not resolve in $C_REPO (this script does not fetch)"
  case $C_NAME in
    tapper)
      need_env TAPPER_RS_TEST_DATABASE_URL "a migrated Postgres that is not the dev stack's; see tapper's CLAUDE.md, section tapper-rs"
      need_env TAPPER_RS_TEST_REDIS_URL "a Redis DB number other than 0, e.g. redis://localhost:6379/1"
      if [ -n "${TAPPER_RS_TEST_DATABASE_URL:-}" ]; then
        need_url_tcp "TAPPER_RS_TEST_DATABASE_URL's Postgres" "$TAPPER_RS_TEST_DATABASE_URL" 5432 "docker compose up -d postgres in tapper"
      fi
      if [ -n "${TAPPER_RS_TEST_REDIS_URL:-}" ]; then
        [ "$(redis_db "$TAPPER_RS_TEST_REDIS_URL")" != 0 ] ||
          problem "TAPPER_RS_TEST_REDIS_URL selects Redis DB 0, which is the dev stack's; use another number, e.g. .../1"
        need_url_tcp "TAPPER_RS_TEST_REDIS_URL's Redis" "$TAPPER_RS_TEST_REDIS_URL" 6379 "docker compose up -d redis in tapper"
      fi
      need_tcp "fake-gcs-server" localhost 4443 "docker compose up -d fake-gcs-server in tapper"
      ;;
    slauth)
      need_cmd uv
      need_default_postgres 5433 "docker compose up -d postgres in slauth"
      ;;
    spendwise)
      need_default_postgres 5437 "docker compose up -d in spendwise-rs; this script does not provision it"
      ;;
  esac
}

# The environment a consumer's cargo runs in: CARGO_TARGET_DIR, plus whatever
# keeps its tests off databases that are not theirs. RUN_UNSET holds `-u NAME`
# pairs for env(1). Sets RUN_ENV and RUN_UNSET.
build_env() {
  RUN_ENV=("CARGO_TARGET_DIR=$SCRATCH/target-$C_NAME")
  RUN_UNSET=()
  case $C_NAME in
    tapper)
      # The differential suite's readiness test reads DATABASE_URL (CI points it
      # at the same database); never let it fall back to the dev stack's.
      RUN_ENV+=("DATABASE_URL=$TAPPER_RS_TEST_DATABASE_URL")
      # CI sets none of these, and tests/gcs.rs requires STORAGE_EMULATOR_HOST
      # to be unset for its real-bucket gate.
      RUN_UNSET+=(-u REDIS_URL -u STORAGE_EMULATOR_HOST -u GCS_BUCKET -u GOOGLE_CREDENTIALS -u TAPPER_RS_GCS_REAL_BUCKET)
      ;;
    slauth | spendwise)
      # Never inherit a DATABASE_URL meant for some other service (tapper's dev
      # shell exports one): either the explicit override or the consumer's own
      # test default.
      RUN_UNSET+=(-u DATABASE_URL -u DATABASE_URL_OVERRIDE)
      if [ -n "$C_DB_URL" ]; then
        RUN_ENV+=("DATABASE_URL=$C_DB_URL")
      fi
      ;;
  esac
}

# Environment assignments as printed in a plan: names only, never values.
show_env() {
  local kv out=''
  for kv in ${RUN_UNSET[@]+"${RUN_UNSET[@]}"}; do out="$out $kv"; done
  for kv in "${RUN_ENV[@]}"; do
    case $kv in
      CARGO_TARGET_DIR=*) out="$out $kv" ;;
      *) out="$out ${kv%%=*}=<value hidden>" ;;
    esac
  done
  printf '%s' "$out"
}

# ------------------------------------------------------------------ steps

# Print the command a step runs, quoted, with the environment shown by name.
show_cmd() { # label cargo-args...
  local label=$1
  shift
  local a
  printf '  %-8s (cd %q && env%s mise exec -- cargo' "$label" "$C_CRATE_DIR" "$(show_env)"
  for a in "$@"; do
    case $a in
      '<'*) printf ' %s' "$a" ;;
      *) printf ' %q' "$a" ;;
    esac
  done
  printf ')\n'
}

# Run `cargo <args>` in the consumer's crate dir through mise, streaming to the
# terminal and to $LOGS/<consumer>-<label>.log, and return cargo's own status.
run_cargo() { # label cargo-args...
  local label=$1 log
  shift
  log=$LOGS/$C_NAME-$label.log
  printf '\n==> %s: %s\n' "$C_NAME" "$label"
  SECONDS=0
  (cd "$C_CRATE_DIR" && env ${RUN_UNSET[@]+"${RUN_UNSET[@]}"} "${RUN_ENV[@]}" mise exec -- cargo "$@") 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  printf '==> %s: %s exited %s after %ss (log: %s)\n' "$C_NAME" "$label" "$rc" "$SECONDS" "$log"
  return "$rc"
}

# After the resolve step: every stridelabs-* package in the consumer's lock
# must be a PATH package (no `source =` line). A git one means the [patch] did
# not take (the consumer names the library under another URL, or the key is
# misspelled), and the "pass" would have tested the pinned crates instead.
check_patched_lock() {
  local lock='' d
  for d in "$C_CRATE_DIR" "$C_DIR"; do
    if [ -f "$d/Cargo.lock" ]; then
      lock=$d/Cargo.lock
      break
    fi
  done
  if [ -z "$lock" ]; then
    echo "!! no Cargo.lock in $C_CRATE_DIR or $C_DIR after resolving"
    return 1
  fi
  # Only [[package]] entries count: a lock also lists [[patch.unused]] patches
  # (ones the consumer does not depend on, e.g. four of the five for limen),
  # which carry no `source` either and would read as patched.
  awk '
    function flush() {
      if (n != "") {
        print "   " n " " v " " s
        if (s ~ /NOT PATCHED/) bad = 1
        seen = 1
      }
      n = ""
    }
    /^\[/ { flush(); inpkg = ($0 == "[[package]]") }
    inpkg && /^name = "stridelabs-/ { n = $3; gsub(/"/, "", n); v = ""; s = "path (patched)" }
    inpkg && /^version = / && n != "" { v = $3; gsub(/"/, "", v) }
    inpkg && /^source = / && n != "" { s = "NOT PATCHED: " $3 }
    END {
      flush()
      if (!seen) { print "   no stridelabs-* package in the lock: this ref does not use the library"; exit 1 }
      exit bad
    }
  ' "$lock"
}

prepare_archive() {
  rm -rf -- "${C_DIR:?}"
  mkdir -p -- "$C_DIR" "$LOGS" || return 1
  git -C "$C_REPO" archive --format=tar "$C_SHA" | tar -x -C "$C_DIR" || return 1
  # mise refuses config files it has not been told to trust. These are byte
  # copies of the consumer's own committed files, so trusting them is safe.
  local f
  while IFS= read -r f; do
    mise trust --quiet "$f" || return 1
  done < <(find "$C_DIR" -maxdepth 3 \( -name .mise.toml -o -name mise.toml \) -type f)
  [ -d "$C_CRATE_DIR" ]
}

# ------------------------------------------------------------- the run

LIB_SHA=$(git -C "$LIB" rev-parse HEAD 2>/dev/null) || die "$LIB is not a git checkout"
LIB_TREE=$(git -C "$LIB" rev-parse 'HEAD^{tree}')
LIB_STATE=$(git -C "$LIB" status --porcelain)
WOULD_REFUSE=0

printf 'library : %s\n' "$LIB"
printf 'lib HEAD: %s\nlib tree: %s\n' "$LIB_SHA" "$LIB_TREE"
if [ -n "$LIB_STATE" ]; then
  printf 'lib state: DIRTY\n%s\n' "$LIB_STATE" | sed 's/^/  /' >&2
  if [ "$DRY_RUN" = 1 ]; then
    printf '  (a real run refuses a dirty library tree, because its SHA and tree id would not name what was tested)\n' >&2
    WOULD_REFUSE=1
  else
    die "the library tree is dirty; commit or stash first so the SHA and tree id above name what is tested"
  fi
else
  printf 'lib state: clean\n'
fi
cat <<'EOF'
mode    : PATCHED development check. The five stridelabs-* crates are [patch]ed to the
          path above and each consumer's lock is re-resolved in its scratch copy (never
          --locked). The binding proof is separate: the consumer's own committed rev pin
          and lock, built with --locked.
EOF

need_cmd git
need_cmd tar
need_cmd mise
if [ "${#PROBLEMS[@]}" -gt 0 ]; then
  printf 'downstream-check: %s\n' "${PROBLEMS[@]}" >&2
  exit 2
fi

PATCH=()
for c in $CRATES; do
  PATCH+=(--config "patch.\"$LIB_URL\".stridelabs-$c.path=\"$LIB/crates/$c\"")
done

# Preflight everything before building anything, so a missing database does
# not surface forty minutes into a tapper build. A REQUIRED consumer that fails
# preflight refuses the whole run; an INFORMATIONAL one is reported not-run.
REFUSED=0
SKIPPED=' '
for c in "${CONSUMERS[@]}"; do
  load_consumer "$c"
  preflight
  if [ "${#PROBLEMS[@]}" -gt 0 ]; then
    if [ "$C_KIND" = required ]; then
      printf '\n%s: REFUSED\n' "$c" >&2
      printf '  - %s\n' "${PROBLEMS[@]}" >&2
      REFUSED=1
    else
      printf '\n%s (informational): NOT RUN\n' "$c" >&2
      printf '  - %s\n' "${PROBLEMS[@]}" >&2
      SKIPPED="$SKIPPED$c "
    fi
  fi
done
[ "$REFUSED" = 0 ] || die "refusing to run: a required consumer is not ready (see above)"

if [ "$DRY_RUN" = 1 ]; then
  for c in "${CONSUMERS[@]}"; do
    load_consumer "$c"
    case "$SKIPPED" in *" $c "*) printf '\n%s: would not run (informational, preflight failed)\n' "$c" && continue ;; esac
    build_env
    printf '\n%s (%s) ref %s -> %s\n' "$c" "$C_KIND" "$C_REF" "$C_SHA"
    printf '  repo     %s\n  archive  %s (fresh each run)\n  crate    %s\n' "$C_REPO" "$C_DIR" "$C_CRATE_DIR"
    show_cmd resolve tree --depth 0 '<patch flags>'
    show_cmd clippy clippy '<patch flags>' "${C_CLIPPY_FLAGS[@]}" -- -D warnings
    show_cmd test test '<patch flags>' ${C_TEST_FLAGS[@]+"${C_TEST_FLAGS[@]}"}
  done
  printf '\n<patch flags> = one --config per crate, for each of: %s\n' "$CRATES"
  printf "  --config 'patch.\"%s\".stridelabs-<crate>.path=\"%s/crates/<crate>\"'\n" "$LIB_URL" "$LIB"
  printf '\ndry run: nothing archived, nothing built (lock %s)\n' "$LOCK"
  [ "$WOULD_REFUSE" = 0 ] || die "a real run would refuse: the library tree is dirty"
  exit 0
fi

# One run at a time: the scratch archives are reused, and the consumers'
# test databases are shared with whoever else is running a gate.
mkdir -p -- "$WORK" "$LOGS" || die "cannot create $WORK"
LOCK_WAITED=0
LOCK_TIMEOUT=${DOWNSTREAM_LOCK_TIMEOUT:-3600}
while ! mkdir "$LOCK" 2>/dev/null; do
  holder=$(cat "$LOCK/pid" 2>/dev/null || true)
  if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
    printf 'removing stale lock left by pid %s\n' "$holder"
    rm -rf -- "$LOCK"
    continue
  fi
  [ "$LOCK_WAITED" -lt "$LOCK_TIMEOUT" ] ||
    die "gave up after ${LOCK_TIMEOUT}s waiting for $LOCK (held by pid ${holder:-unknown}; remove it if that run is gone)"
  [ $((LOCK_WAITED % 30)) -ne 0 ] || printf 'waiting for %s (held by pid %s)\n' "$LOCK" "${holder:-unknown}"
  sleep 5
  LOCK_WAITED=$((LOCK_WAITED + 5))
done
printf '%s\n' "$$" >"$LOCK/pid"
trap 'rm -rf -- "$LOCK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# One table row per consumer, formatted where it is recorded.
row() { printf '%-10s %-4s %-13s %-13s %-8s %-8s %-8s\n' "$@"; }
LIB_SHORT=${LIB_SHA:0:12}
ROWS=()
ANY_REQUIRED_FAILED=0
REQUIRED_RAN=0

for c in "${CONSUMERS[@]}"; do
  load_consumer "$c"
  case "$SKIPPED" in
    *" $c "*)
      ROWS+=("$(row "$c" no - "$LIB_SHORT" 'NOT RUN' 'NOT RUN' 'NOT RUN')")
      continue
      ;;
  esac
  build_env
  printf '\n######## %s (%s) ref %s -> %s\n' "$c" "$C_KIND" "$C_REF" "$C_SHA"
  res=FAIL clip=- tst=-
  if ! prepare_archive; then
    echo "!! could not archive $C_REF of $C_REPO into $C_DIR"
  elif run_cargo resolve tree --depth 0 "${PATCH[@]}" && check_patched_lock; then
    res=PASS
    if run_cargo clippy clippy "${PATCH[@]}" "${C_CLIPPY_FLAGS[@]}" -- -D warnings; then
      clip=PASS
    else
      clip=FAIL
    fi
    if run_cargo test test "${PATCH[@]}" ${C_TEST_FLAGS[@]+"${C_TEST_FLAGS[@]}"}; then
      tst=PASS
    else
      tst=FAIL
    fi
  fi
  if [ "$C_KIND" = required ]; then
    req=yes
    REQUIRED_RAN=$((REQUIRED_RAN + 1))
    if [ "$res" != PASS ] || [ "$clip" != PASS ] || [ "$tst" != PASS ]; then
      ANY_REQUIRED_FAILED=1
    fi
  else
    req=no
  fi
  ROWS+=("$(row "$c" "$req" "${C_SHA:0:12}" "$LIB_SHORT" "$res" "$clip" "$tst")")
done

printf '\n'
printf 'library %s (tree %s)\n' "$LIB_SHA" "$LIB_TREE"
printf 'PATCHED development check, not --locked: see the header of this script.\n\n'
row consumer req ref-sha lib-sha resolve clippy test
printf '%s\n' "${ROWS[@]}"

# The check must not write into the library (its target dir lives elsewhere).
after=$(git -C "$LIB" status --porcelain)
if [ -n "$after" ]; then
  printf '\n!! the run changed the library tree:\n%s\n' "$after" >&2
  exit 1
fi

if [ "$ANY_REQUIRED_FAILED" = 1 ]; then
  printf '\nRESULT: FAIL (a required consumer did not pass)\n'
  exit 1
fi
if [ "$REQUIRED_RAN" = 0 ]; then
  printf '\nRESULT: no required consumer was selected; the informational rows above decide nothing\n'
  exit 0
fi
printf '\nRESULT: PASS (every required consumer passed; informational ones are shown above)\n'
