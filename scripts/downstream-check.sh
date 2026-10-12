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
#     patched path packages (and anything new they pull in) can enter it,
#     starting with `cargo update -p` for every stridelabs-* package it holds
#     (a [patch] at another version than the locked one is silently unused).
#     That makes this a DEVELOPMENT check. The binding proof builds each
#     consumer from its own committed rev pin and Cargo.lock with --locked.
#   - The table's `patch` column is the first step: every locked stridelabs-*
#     package moved onto the patch (`cargo update -p`), then `cargo metadata`
#     (with the feature flags clippy and test use) proving each one is this
#     checkout's own crate. clippy and test run only when it passed.
#   - Every build uses CARGO_TARGET_DIR=$SCRATCH/target-<consumer>.
#   - The scratch root, the library and each consumer repo are resolved ONCE
#     to their physical paths, and only those paths are used from then on
#     (archive, extraction, logs, lock, target dirs), so a symlink retargeted
#     after the checks cannot redirect a removal.
#   - Nothing is removed unless it resolves, symlinks and all, to
#     $SCRATCH/downstream/<consumer>, or is this script's own lock
#     ($SCRATCH/downstream/.lock). A consumer repo or the library that is,
#     holds or sits inside $SCRATCH/downstream is refused before anything
#     happens (a dry run refuses too), so a mistaken DOWNSTREAM_<NAME>_REPO
#     cannot be the directory that is recreated.
#   - Everything cargo prints passes through `redact` before the terminal or a
#     log sees it: URL userinfo and the values of token/password/secret/key
#     parameters are masked (a failing test can print the URL it could not
#     authenticate with). The script's own messages name a host and a port,
#     never a URL. No raw cargo output is kept: `cargo metadata`'s JSON exists
#     only while jq reads it, and its stderr is kept in memory and logged masked.
#   - Once the lock is held the library's HEAD, tree id and (untracked files
#     included) state are read again; they are checked once more at the end, and
#     the run fails if the library moved while the consumers were tested.
#
# Exit status: 0 when every REQUIRED consumer (tapper, slauth, limen) passed;
# 1 when one failed, or when the run changed or moved the library; 2 when it
# refused to start (usage, dirty library tree, paths that overlap, missing env
# or service).
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
# Needs git, tar, mise and jq (cargo metadata proves the patch applied).
# Written for bash 3.2 (macOS /bin/bash) as well as current bash.

set -uo pipefail

LIB=${DOWNSTREAM_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SCRATCH=${DOWNSTREAM_SCRATCH:-/Volumes/miniext/scratch-011}
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

# The physical (symlink-free) absolute form of a path. A tail that does not
# exist yet is kept as written, under its deepest existing parent.
canon() {
  local p=$1 tail='' base
  case $p in /*) ;; *) p=$PWD/$p ;; esac
  while [ "${p%/}" != "$p" ] && [ "$p" != / ]; do p=${p%/}; done
  while [ ! -d "$p" ]; do
    tail=/${p##*/}$tail
    p=${p%/*}
    while [ "${p%/}" != "$p" ] && [ "$p" != / ]; do p=${p%/}; done
    [ -n "$p" ] || p=/
  done
  case $tail/ in */./* | */../*) return 1 ;; esac
  base=$(cd "$p" && pwd -P) || return 1
  p=${base%/}$tail
  printf '%s' "${p:-/}"
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

# --------------------------------------------------- paths, resolved once

# The scratch root and the library are resolved to their physical paths HERE,
# once, and every later use (archive, extraction, logs, lock, target dirs, the
# [patch] paths, git -C) goes through the resolved paths, never the ones given.
# A symlink retargeted after the safety checks below therefore changes nothing.
SCRATCH_ARG=$SCRATCH
SCRATCH=$(canon "$SCRATCH_ARG") || die "cannot resolve the scratch directory $SCRATCH_ARG"
LIB_ARG=$LIB
LIB=$(canon "$LIB_ARG") || die "cannot resolve the library path $LIB_ARG"
WORK=$SCRATCH/downstream
LOGS=$WORK/logs
LOCK=$WORK/.lock
TAKEOVER=$LOCK.takeover

# ------------------------------------------------------------ consumer table

# The part of the cargo flags that selects features. `cargo metadata` must see
# the graph the clippy and test steps build, or an optional stridelabs-*
# dependency that --features / --all-features switches on (and that a consumer
# could vendor) would not be in what the proof looks at. Sets C_FEATURE_FLAGS
# from the flags it is given.
feature_flags() { # flags...
  local a pend='' seen=' '
  C_FEATURE_FLAGS=()
  for a in "$@"; do
    if [ -n "$pend" ]; then
      case $seen in
        *" $pend $a "*) ;;
        *)
          seen="$seen$pend $a "
          C_FEATURE_FLAGS+=("$pend" "$a")
          ;;
      esac
      pend=''
      continue
    fi
    case $a in
      --features | -F) pend=$a ;;
      --features=* | -F?* | --all-features | --no-default-features)
        case $seen in
          *" $a "*) ;;
          *)
            seen="$seen$a "
            C_FEATURE_FLAGS+=("$a")
            ;;
        esac
        ;;
    esac
  done
}

# Sets C_* for one consumer. The clippy and test flags are the ones that
# consumer's own CI uses, minus --locked (see the header): tapper-rs runs
# clippy with --all-features (its CI job tapper-rs-check), limen and spendwise
# test with --all, slauth with plain `cargo test`. The command line's extra
# flags are appended to both. The repo path is resolved here, once per call, so
# no later step goes through a symlink.
load_consumer() {
  local var real
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
  feature_flags "${C_CLIPPY_FLAGS[@]}" ${C_TEST_FLAGS[@]+"${C_TEST_FLAGS[@]}"}
  var=DOWNSTREAM_${C_UPPER}_REPO
  C_REPO=${!var:-$C_REPO}
  real=$(canon "$C_REPO") && C_REPO=$real
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

# True when the physical paths $1 and $2 are the same, or one holds the other.
nested() {
  local a=${1%/}/ b=${2%/}/
  case $a in "$b"*) return 0 ;; esac
  case $b in "$a"*) return 0 ;; esac
  return 1
}

# A consumer's output can carry credentials: a panic that prints the URL it
# failed to authenticate with, a readiness failure that prints DATABASE_URL.
# This filter keeps them off the terminal and out of the logs:
#   scheme://user:pass@host  ->  scheme://***@host
#   name=value, for a name containing token, password, passwd, secret or key
#   (any case), in a query string or on its own  ->  name=***
# Deliberately blunt: an over-masked line costs a look at the raw run, a leak
# costs a rotation. It is line-buffered so a long build still streams.
REDACT_KEYS='[Tt][Oo][Kk][Ee][Nn]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Kk][Ee][Yy]'
redact() {
  sed -u -E \
    -e "s#([A-Za-z][A-Za-z0-9+.-]*://)[^[:space:]/\"']*@#\1***@#g" \
    -e "s#(^|[?&;,[:space:]\"'(])([A-Za-z0-9_.-]*($REDACT_KEYS)[A-Za-z0-9_.-]*)=[^&;,[:space:]\"')]*#\1\2=***#g"
}

# The database number a redis:// URL selects, read the way redis-rs reads it:
# the path with its slashes trimmed, an optional `+`, then digits (so `00` and
# `+0` are database 0). The query and fragment go first, so a `/` inside them
# is not a path. Prints the number, 0 when the URL names none, or `invalid`
# when the path is not a number.
redis_db() {
  local u=${1#*://}
  u=${u%%[?#]*}
  case $u in
    */*) u=${u#*/} ;;
    *) u='' ;;
  esac
  while [ "${u#/}" != "$u" ]; do u=${u#/}; done
  while [ "${u%/}" != "$u" ]; do u=${u%/}; done
  u=${u#+}
  case $u in
    *[!0-9]*) printf invalid ;;
    *)
      while [ "${u#0}" != "$u" ]; do u=${u#0}; done
      printf '%s' "${u:-0}"
      ;;
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

# need_tcp on the host and port a URL names. Only what is plainly a hostname
# and a port is ever echoed: a URL that does not parse the way a URL should
# could otherwise carry its credentials into the message.
need_url_tcp() { # label url default-port hint
  local a=${2#*://} host port
  a=${a%%[/?]*}
  a=${a##*@}
  case $a in
    *:*)
      host=${a%%:*}
      port=${a##*:}
      ;;
    *)
      host=$a
      port=$3
      ;;
  esac
  case $host in '' | *[!A-Za-z0-9._-]*)
    problem "$1: no host can be read from its URL"
    return
    ;;
  esac
  case $port in '' | *[!0-9]*)
    problem "$1: no port can be read from its URL"
    return
    ;;
  esac
  need_tcp "$1" "$host" "$port" "$4"
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
        case $(redis_db "$TAPPER_RS_TEST_REDIS_URL") in
          invalid) problem "TAPPER_RS_TEST_REDIS_URL's database is not a number; use another number than 0, e.g. .../1" ;;
          0) problem "TAPPER_RS_TEST_REDIS_URL selects Redis DB 0, which is the dev stack's; use another number, e.g. .../1" ;;
        esac
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

# `cargo <args>` in the consumer's crate dir, through mise, in its environment.
cargo_in_crate() { # cargo-args...
  (cd "$C_CRATE_DIR" && env ${RUN_UNSET[@]+"${RUN_UNSET[@]}"} "${RUN_ENV[@]}" mise exec -- cargo "$@")
}

# Run `cargo <args>`, streaming to the terminal and to $LOGS/<consumer>-<label>.log
# (both only ever see `redact`ed text), and return cargo's own status.
run_cargo() { # label cargo-args...
  local label=$1 log
  shift
  log=$LOGS/$C_NAME-$label.log
  printf '\n==> %s: %s\n' "$C_NAME" "$label"
  SECONDS=0
  cargo_in_crate "$@" 2>&1 | redact | tee "$log"
  local rc=${PIPESTATUS[0]}
  printf '==> %s: %s exited %s after %ss (log: %s)\n' "$C_NAME" "$label" "$rc" "$SECONDS" "$log"
  return "$rc"
}

# A [patch] whose version differs from the one the consumer's lock holds (a
# release bump: the lock says 0.4.0, the candidate is 0.5.0) is silently left
# unused, so first move every locked stridelabs-* package onto the patch.
# CI's downstream-limen does the same in its "Move limen's locked stridelabs
# packages onto the patch" step; keep the two in step. A lock that names no
# stridelabs-* package fails here, as it does there: a consumer that does not
# use the library cannot pass the proof below either, so say so first.
adopt_patch() {
  local lock=$C_CRATE_DIR/Cargo.lock n
  local names=()
  if [ ! -f "$lock" ]; then
    echo "!! $C_NAME has no Cargo.lock in $C_CRATE_DIR"
    return 1
  fi
  while IFS= read -r n; do
    names+=(-p "$n")
  done < <(sed -n 's/^name = "\(stridelabs-[a-z-]*\)"$/\1/p' "$lock" | sort -u)
  if [ "${#names[@]}" -eq 0 ]; then
    echo "!! $C_NAME's Cargo.lock names no stridelabs-* package"
    return 1
  fi
  run_cargo adopt update "${PATCH[@]}" "${names[@]}"
}

# After adopt_patch: every stridelabs-* package in the consumer's resolved graph
# (the one its clippy and test steps build: same feature flags) must be THIS
# checkout's crate of that name, a path package whose manifest is
# $LIB/crates/<name>/Cargo.toml. A git source means the [patch] did not take
# (the consumer names the library under another URL, or the key is
# misspelled); a path package from anywhere else is a vendored copy that also
# has no `source`. Either way the "pass" would have tested other code.
# CI's "Prove the patch took effect" step is the same check.
check_patched_graph() {
  local meta=$LOGS/$C_NAME-metadata.json err rc
  local pkgs name version source manifest dir seen=0 bad=0
  # The raw JSON exists only while jq reads it, and stderr never touches the
  # disk raw: what lands in a log is masked.
  err=$( (
    umask 077
    cargo_in_crate metadata --format-version 1 ${C_FEATURE_FLAGS[@]+"${C_FEATURE_FLAGS[@]}"} "${PATCH[@]}" 2>&1 >"$meta"
  ))
  rc=$?
  printf '%s\n' "$err" | redact >"$LOGS/$C_NAME-metadata.log"
  if [ "$rc" -ne 0 ]; then
    rm -f -- "$meta"
    echo "!! cargo metadata failed:"
    printf '%s\n' "$err" | redact
    return 1
  fi
  pkgs=$(jq -r '.packages[] | select(.name | startswith("stridelabs-"))
    | [.name, .version, (.source // "path"), .manifest_path] | @tsv' "$meta" | sort)
  rc=$?
  rm -f -- "$meta"
  if [ "$rc" -ne 0 ]; then
    echo "!! cannot read cargo metadata's output"
    return 1
  fi
  while IFS=$'\t' read -r name version source manifest; do
    [ -n "$name" ] || continue
    seen=1
    dir=$(canon "$(dirname "$manifest")")
    if [ "$source" = path ] && [ "$dir" = "$LIB/crates/${name#stridelabs-}" ]; then
      echo "   $name $version path (patched)"
    else
      [ "$source" = path ] && source="a path package outside this checkout: $dir"
      echo "   $name $version NOT PATCHED: $source" | redact
      bad=1
    fi
  done <<<"$pkgs"
  if [ "$seen" = 0 ]; then
    echo "   no stridelabs-* package in the resolved graph: this ref does not use the library"
    return 1
  fi
  return "$bad"
}

prepare_archive() {
  # The one rm -rf of a consumer archive (the others remove only the lock).
  # It only ever removes what resolves to $WORK/<consumer>, checked here and
  # not only up front; $WORK is under the scratch root resolved at the start.
  [ "$(canon "$C_DIR")" = "$WORK/$C_NAME" ] || {
    echo "!! refusing to remove $C_DIR: it does not resolve to $WORK/$C_NAME"
    return 1
  }
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

# What the library is right now: HEAD, its tree id, and whether the working
# tree differs from it. Untracked files count whatever status.showUntrackedFiles
# says (an untracked module is still compiled), and so does a changed submodule.
read_library() {
  LIB_SHA=$(git -C "$LIB" rev-parse HEAD 2>/dev/null) || return 1
  LIB_TREE=$(git -C "$LIB" rev-parse 'HEAD^{tree}') || return 1
  LIB_STATE=$(git -C "$LIB" status --porcelain --untracked-files=all --ignore-submodules=none)
}
read_library || die "$LIB is not a git checkout"
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
need_cmd jq
if [ "${#PROBLEMS[@]}" -gt 0 ]; then
  printf 'downstream-check: %s\n' "${PROBLEMS[@]}" >&2
  exit 2
fi

# Path safety, before anything is created or removed (a dry run refuses too).
# Each run recreates $WORK/<consumer> with rm -rf, so nothing the run reads
# from may be that directory, sit inside $WORK, or hold it; and $WORK and each
# archive directory must be where they say once symlinks are resolved. The
# scratch root, the library and the repos are already physical paths.
PATH_BAD=0
path_problem() {
  printf 'downstream-check: %s\n' "$*" >&2
  PATH_BAD=1
}
[ "$(canon "$WORK")" = "$WORK" ] ||
  path_problem "$WORK does not resolve to itself (a symlink?); nothing under it would be safe to remove"
if nested "$LIB" "$WORK"; then
  path_problem "the library ($LIB) overlaps the archive root $WORK; point DOWNSTREAM_LIB or DOWNSTREAM_SCRATCH elsewhere"
fi
for c in "${CONSUMERS[@]}"; do
  load_consumer "$c"
  if nested "$C_REPO" "$WORK"; then
    path_problem "$c's repo ($C_REPO) overlaps the archive root $WORK; point DOWNSTREAM_${C_UPPER}_REPO or DOWNSTREAM_SCRATCH elsewhere"
  fi
  [ "$(canon "$C_DIR")" = "$WORK/$c" ] ||
    path_problem "$C_DIR does not resolve to $WORK/$c (a symlink?); it would not be safe to remove"
done
[ "$PATH_BAD" = 0 ] || exit 2

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
    show_cmd adopt update '<patch flags>' '-p <each stridelabs-* package in its lock>'
    show_cmd proof metadata --format-version 1 '<patch flags>' ${C_FEATURE_FLAGS[@]+"${C_FEATURE_FLAGS[@]}"}
    show_cmd clippy clippy '<patch flags>' "${C_CLIPPY_FLAGS[@]}" -- -D warnings
    show_cmd test test '<patch flags>' ${C_TEST_FLAGS[@]+"${C_TEST_FLAGS[@]}"}
  done
  printf '\n<patch flags> = one --config per crate, for each of: %s\n' "$CRATES"
  printf "  --config 'patch.\"%s\".stridelabs-<crate>.path=\"%s/crates/<crate>\"'\n" "$LIB_URL" "$LIB"
  printf '\ndry run: nothing archived, nothing built (lock %s)\n' "$LOCK"
  [ "$WOULD_REFUSE" = 0 ] || die "a real run would refuse: the library tree is dirty"
  exit 0
fi

# Take over the lock of a holder that has died, without ever removing a live
# one. Contenders that saw the same dead holder race to remove it, and the one
# that loses must not remove the lock the winner then took. So a removal
# happens only inside $TAKEOVER (one contender at a time), after re-reading who
# holds the lock, and by renaming it away first. Returns 0 when it removed it.
reap_stale_lock() { # pid-seen-dead
  local now rc=1
  mkdir "$TAKEOVER" 2>/dev/null || return 1
  now=$(cat "$LOCK/pid" 2>/dev/null || true)
  if [ "$now" = "$1" ] && ! kill -0 "$1" 2>/dev/null; then
    printf 'removing stale lock left by pid %s\n' "$1"
    mv "$LOCK" "$LOCK.stale.$$" && rm -rf -- "$LOCK.stale.$$" && rc=0
  fi
  rmdir "$TAKEOVER"
  return "$rc"
}

# One run at a time: the scratch archives are reused, and the consumers'
# test databases are shared with whoever else is running a gate.
mkdir -p -- "$WORK" "$LOGS" || die "cannot create $WORK"
LOCK_WAITED=0
LOCK_TIMEOUT=${DOWNSTREAM_LOCK_TIMEOUT:-3600}
while ! mkdir "$LOCK" 2>/dev/null; do
  holder=$(cat "$LOCK/pid" 2>/dev/null || true)
  if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
    if reap_stale_lock "$holder"; then
      continue
    fi
    holder=$(cat "$LOCK/pid" 2>/dev/null || true) # not the one seen dead: someone took it
  fi
  [ "$LOCK_WAITED" -lt "$LOCK_TIMEOUT" ] || {
    stuck=it
    [ ! -d "$TAKEOVER" ] || stuck="$LOCK and $TAKEOVER"
    die "gave up after ${LOCK_TIMEOUT}s waiting for $LOCK (held by pid ${holder:-unknown}; remove $stuck if that run is gone)"
  }
  [ $((LOCK_WAITED % 30)) -ne 0 ] || printf 'waiting for %s (held by pid %s)\n' "$LOCK" "${holder:-unknown}"
  sleep 5
  LOCK_WAITED=$((LOCK_WAITED + 5))
done
printf '%s\n' "$$" >"$LOCK/pid"
trap 'rm -rf -- "$LOCK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The library can change while this run waited for the lock (or sat in
# preflight above). What is tested is what is there now, so read it again, and
# say so when it is not what was printed at the start.
SEEN_SHA=$LIB_SHA SEEN_TREE=$LIB_TREE
read_library || die "$LIB is not a git checkout"
[ -z "$LIB_STATE" ] || die "the library tree became dirty while waiting for the lock; commit or stash first so the SHA and tree id name what is tested"
if [ "$LIB_SHA" != "$SEEN_SHA" ] || [ "$LIB_TREE" != "$SEEN_TREE" ]; then
  printf 'the library moved while waiting for the lock; testing the new one:\nlib HEAD: %s\nlib tree: %s\n' "$LIB_SHA" "$LIB_TREE"
fi

# One table row per consumer, formatted where it is recorded.
row() { printf '%-10s %-4s %-13s %-13s %-8s %-8s %-8s\n' "$@"; }
START_SHA=$LIB_SHA START_TREE=$LIB_TREE
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
  elif adopt_patch && check_patched_graph; then
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
row consumer req ref-sha lib-sha patch clippy test
printf '%s\n' "${ROWS[@]}"

# The check must not write into the library (its target dir lives elsewhere),
# and the library must still be the commit and tree the rows above name.
read_library || die "$LIB is not a git checkout"
if [ -n "$LIB_STATE" ]; then
  printf '\n!! the run changed the library tree:\n%s\n' "$LIB_STATE" >&2
  exit 1
fi
if [ "$LIB_SHA" != "$START_SHA" ] || [ "$LIB_TREE" != "$START_TREE" ]; then
  printf '\n!! the library moved during the run: HEAD %s -> %s, tree %s -> %s\n' \
    "$START_SHA" "$LIB_SHA" "$START_TREE" "$LIB_TREE" >&2
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
