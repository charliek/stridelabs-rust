#!/usr/bin/env bash
# Build and test a CONSUMER of stridelabs-rust against THIS checkout of the
# library: the local gate that runs before a library change is tagged.
#
#   scripts/downstream-check.sh [--dry-run] <consumer[,consumer...]|all> <ref> [extra cargo flags]
#
# consumer  tapper | slauth | limen | imgmcp | spendwise | slaudio | lumen | parcel
#           (limen is also checked in CI, by the `downstream-limen` job; the
#           others are private repos whose test output must not land in a public
#           Actions log, so they are checked only here. `limen` is the public
#           consumer repo of that name; `lumen` is a different, private one.)
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
#   - Every stridelabs-* crate is overridden with `--config
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
#     to their physical paths (a repo at the up-front check, then pinned), and
#     only those paths are used from then on (archive, extraction, logs, lock,
#     target dirs), so a symlink retargeted after the checks cannot redirect a
#     removal or change what is archived.
#   - Nothing is removed unless it resolves, symlinks and all, to
#     $SCRATCH/downstream/<consumer>, or is this script's own lock
#     ($SCRATCH/downstream/.lock) or its logs directory, which is recreated
#     empty (mode 700) once the lock is held, so no log is ever written
#     through a symlink somebody left there. A consumer repo or the library that is,
#     holds or sits inside $SCRATCH/downstream is refused before anything
#     happens (a dry run refuses too), so a mistaken DOWNSTREAM_<NAME>_REPO
#     cannot be the directory that is recreated.
#   - Everything cargo prints passes through `redact` before the terminal or a
#     log sees it: URL userinfo and the values of token/password/secret/key
#     parameters are masked (a failing test can print the URL it could not
#     authenticate with). The script's own messages name a host and a port,
#     never a URL. No raw cargo output is kept: `cargo metadata`'s JSON is a
#     mktemp file in the logs directory that exists only while jq reads it
#     (removed on any exit, a signal included), and its stderr is kept in
#     memory and logged masked.
#   - Once the lock is held the library's HEAD, tree id and (untracked files
#     included) state are read again; they are checked once more at the end, and
#     the run fails if the library moved while the consumers were tested.
#
# Exit status: 0 when every REQUIRED consumer (tapper, slauth, limen, imgmcp)
# passed; 1 when one failed, or when the run changed or moved the library; 2
# when it refused to start (usage, dirty library tree, paths that overlap,
# missing env or service).
# spendwise, slaudio, lumen and parcel are INFORMATIONAL: their results are printed but
# never decide the exit.
#
# Environment (names only; this script never prints a value):
#   tapper     TAPPER_RS_TEST_DATABASE_URL  a MIGRATED Postgres that is not the dev stack's
#              TAPPER_RS_TEST_REDIS_URL     a Redis DB number other than 0
#              and fake-gcs-server on 127.0.0.1:4443 (`docker compose up -d fake-gcs-server`),
#              named to the tests by TAPPER_RS_TEST_GCS_EMULATOR_URL (loopback
#              only; tapper's tests have no default for it). The run sets it to
#              http://127.0.0.1:4443 unless the caller already set it, in which
#              case the caller's value is passed through and is what preflight
#              checks. A tapper ref from before tapper plan 017 C-3 does not read
#              it and uses 4443 itself, so setting it is harmless there.
#              There is no default for the database and Redis variables, on
#              purpose: tapper's own tests fail rather than skip without them,
#              and a default would be the dev database. See "tapper-rs" in
#              tapper's CLAUDE.md.
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
#   imgmcp     nothing (its tests are hermetic).
#   slaudio    its Rust port lives on the `rust-port` branch (main has no
#              backend-rs), so pass DOWNSTREAM_SLAUDIO_REF=rust-port (or
#              origin/rust-port) when the ref argument names another branch.
#              A Postgres server and a Redis: SLAUDIO_TEST_DATABASE_URL and
#              SLAUDIO_TEST_REDIS_URL, defaulting (in its own tests too) to
#              localhost:5435 and localhost:6381 (`docker compose up -d
#              postgres redis` in slaudio). DATABASE_URL and REDIS_URL are never
#              read. A host tz database (TZDIR, else /usr/share/zoneinfo)
#              older than 2026c only prints a note (most of its tz tests bring
#              their own synthetic database), except that a ref holding
#              slaudio-core/src/schedule/tests/ (which read the host database)
#              is refused below 2024b. A ref holding
#              slaudio-worker/tests/scheduler_restate.rs also needs the local
#              Restate server (`docker compose up -d restate`): admin on
#              localhost:9070 and ingress on localhost:8088, or
#              SLAUDIO_TEST_RESTATE_ADMIN_URL / _INGRESS_URL.
#   lumen      its Rust port is the lumen-rs/ workspace (`.` and tools/fakes) on
#              lumen's `main`. Pass origin/main (or DOWNSTREAM_LUMEN_REF=origin/main):
#              this script does not fetch, and a local `main` can lag. A Postgres
#              database and a Redis: LUMEN_RS_TEST_DATABASE_URL and
#              LUMEN_RS_TEST_REDIS_URL, defaulting here (lumen-rs has no default of its
#              own: unset, its tests FAIL) to lumen's compose, localhost:55432/lumen_rs_test
#              and localhost:56379 DB 1 (`docker compose up -d postgres redis` in
#              lumen). A Redis DB 0 is refused. DATABASE_URL and REDIS_URL are never
#              read, and the service's own settings (WORKOS_*, GCS_*,
#              STORAGE_EMULATOR_HOST, LUMEN_HERMETIC, LUMEN_RS_DATABASE_URL, the proxy
#              variables, the *_API_KEY variables) are unset for the run.
#              Its GCS suites need lumen's own fake-gcs-server, named by
#              LUMEN_RS_TEST_GCS_URL (required by the tests, loopback only),
#              defaulting here to http://localhost:54443 (`docker compose up -d
#              fake-gcs` in lumen). Never 4443, which is tapper's emulator.
#              The suites also create and drop scratch databases (lumen_rs_scratch_*)
#              on the Postgres server, so its user needs CREATEDB. Clippy and test
#              run lumen's CI flags (--workspace); its separate `--features
#              dev-login` test run is not repeated here (clippy --all-features does
#              compile it).
#   parcel     its Rust workspace is the repo root (`.`) on parcel's `main`. Pass
#              origin/main (or DOWNSTREAM_PARCEL_REF=origin/main): this script does
#              not fetch. Clippy and test run parcel's CI flags (--workspace
#              --all-targets --all-features, and --workspace); its production-feature
#              clippy, cargo deny, the crypto guard, the second `DATABASE_URL`-set
#              test pass, Spectral and the pytest functional suite are not repeated
#              here. Its server tests need parcel's compose Postgres, which has no
#              URL variable of its own: unset DATABASE_URL they use
#              postgres://postgres:localdev@localhost:5439/parcel_test (the database
#              is created on demand) and its fake-gcs-server 1.52 at
#              http://localhost:4447 (`docker compose up -d` in parcel; the emulator
#              address is fixed in its tests). Port 5439 is also the example
#              alternative port in this library's CLAUDE.md (`STRIDELABS_PG_PORT=5439`):
#              if you moved this library's Postgres there, parcel's preflight check
#              passes on the wrong server and its tests fail on authentication or a
#              missing role. Stop that one, move the library's to another port, or
#              point parcel at the right server with DOWNSTREAM_PARCEL_DATABASE_URL
#              (passed to its run as DATABASE_URL; a loopback URL naming a database
#              that already exists, because with DATABASE_URL set parcel's harness
#              creates schemas in it and does not create the database). Preflight
#              refuses an override that names no database or `parcel` (parcel's DEV
#              database: the harness drops the old schemas it finds in the one it
#              is given), or whose query sets host, hostaddr, port or dbname (sqlx
#              applies them over the URL, so the endpoint checked would not be the
#              one used), saying which rule and never the value. The
#              service's own settings (DATABASE_URL otherwise, STORAGE_EMULATOR_HOST,
#              GOOGLE_CREDENTIALS, APP_ENV, the proxy variables, ...) are unset for
#              the run by name, and every exported variable starting AUTH_, SLAUTH_,
#              GCS_, BLOB_ or PARCEL_ by prefix (parcel builds its provider settings'
#              names, AUTH_<PROVIDER>_*, at run time).
#
# Paths. Nothing here names a machine: every default is relative to the
# library checkout or to $HOME, and every one can be overridden.
#   A consumer's repo is the first <root>/<dir> that is a git checkout, for each
#   root in DOWNSTREAM_PROJECTS (colon-separated; default: the directory the
#   library checkout sits in, then $HOME/projects). <dir> is the consumer's
#   name, except spendwise-rs. DOWNSTREAM_<NAME>_REPO overrides one consumer.
#   DOWNSTREAM_LIB overrides the library path (default: the checkout this
#   script is in), DOWNSTREAM_SCRATCH the scratch root (default:
#   ${XDG_CACHE_HOME:-$HOME/.cache}/stridelabs-downstream; the target dirs are
#   large, so point it at a roomy disk), DOWNSTREAM_LOCK_TIMEOUT the seconds to
#   wait for the lock (default 3600).
#
# Needs git, tar, mise and jq (cargo metadata proves the patch applied).
# Written for bash 3.2 (macOS /bin/bash) as well as current bash.

set -uo pipefail

LIB=${DOWNSTREAM_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
# Empty when no default can be formed (HOME unset); refused once die exists.
if [ -n "${DOWNSTREAM_SCRATCH:-}" ]; then
  SCRATCH=$DOWNSTREAM_SCRATCH
elif [ -n "${XDG_CACHE_HOME:-}" ]; then
  SCRATCH=$XDG_CACHE_HOME/stridelabs-downstream
elif [ -n "${HOME:-}" ]; then
  SCRATCH=$HOME/.cache/stridelabs-downstream
else
  SCRATCH=''
fi
LIB_URL='https://github.com/charliek/stridelabs-rust.git'
CRATES='config observability http auth testing mcp redis gcp inworld postgres perplexity'
KNOWN_CONSUMERS='tapper slauth limen imgmcp spendwise slaudio lumen parcel'

usage() {
  cat >&2 <<'EOF'
usage: scripts/downstream-check.sh [--dry-run] <consumer[,consumer...]|all> <ref> [extra cargo flags]
  consumer: tapper | slauth | limen | imgmcp | spendwise | slaudio | lumen | parcel
            (spendwise, slaudio, lumen and parcel are informational)
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
[ -n "$SCRATCH" ] || die "no scratch directory: HOME is not set (set DOWNSTREAM_SCRATCH)"
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

# The default repo path of a consumer directory: the first <root>/<dir> that is
# a git checkout (a worktree's .git file counts), for each root in
# DOWNSTREAM_PROJECTS. With none found it prints the first root's candidate, so
# preflight names a concrete path and the variable that overrides it. It prints
# NOTHING when there is no usable root at all (every entry empty, HOME unset
# and no override); load_consumer refuses that rather than letting an empty
# path resolve to the current directory.
default_repo() ( # dir
  # A subshell body: `set -f` and IFS stay inside it. Splitting on ':' with
  # globbing off takes every root literally ('team[1]' is not 'team1', and a
  # newline inside a root is kept). ${HOME:+...} drops the home root when HOME
  # is unset instead of tripping `set -u`.
  set -f
  IFS=:
  first=''
  for root in ${DOWNSTREAM_PROJECTS:-$(dirname "$LIB")${HOME:+:$HOME/projects}}; do
    [ -n "$root" ] || continue
    [ -n "$first" ] || first=${root%/}/$1
    if [ -d "${root%/}/$1/.git" ] || [ -f "${root%/}/$1/.git" ]; then
      printf '%s' "${root%/}/$1"
      exit 0
    fi
  done
  printf '%s' "$first"
)

# Sets C_* for one consumer. The clippy and test flags are the ones that
# consumer's own CI uses, minus --locked (see the header): tapper-rs runs
# clippy with --all-features (its CI job tapper-rs-check), limen and spendwise
# test with --all, slauth and imgmcp with plain `cargo test` (imgmcp's clippy
# with --all-features), slaudio's backend-rs workspace with --workspace
# --all-features (its CI job), lumen's lumen-rs workspace clippy with
# --workspace --all-targets --all-features and test with --workspace (its CI
# job lumen-rs-check), parcel's root workspace clippy with --workspace
# --all-targets --all-features and test with --workspace (its CI job rust). The
# command line's extra flags are appended to
# both. The repo path is the pinned physical one once the path-safety check has
# run.
load_consumer() {
  local var
  C_NAME=$1
  C_UPPER=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
  C_TEST_FLAGS=()
  case $1 in
    tapper)
      C_REPO=$(default_repo tapper)
      C_CRATE=tapper-rs
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets --all-features)
      ;;
    slauth)
      C_REPO=$(default_repo slauth)
      C_CRATE=backend-rs
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets)
      ;;
    limen)
      C_REPO=$(default_repo limen)
      C_CRATE=.
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets)
      C_TEST_FLAGS=(--all)
      ;;
    imgmcp)
      C_REPO=$(default_repo imgmcp)
      C_CRATE=.
      C_KIND=required
      C_CLIPPY_FLAGS=(--all-targets --all-features)
      ;;
    spendwise)
      C_REPO=$(default_repo spendwise-rs)
      C_CRATE=backend
      C_KIND=informational
      C_CLIPPY_FLAGS=(--all-targets)
      C_TEST_FLAGS=(--all)
      ;;
    slaudio)
      C_REPO=$(default_repo slaudio)
      C_CRATE=backend-rs
      C_KIND=informational
      C_CLIPPY_FLAGS=(--workspace --all-targets --all-features)
      C_TEST_FLAGS=(--workspace --all-features)
      ;;
    lumen)
      C_REPO=$(default_repo lumen)
      C_CRATE=lumen-rs
      C_KIND=informational
      C_CLIPPY_FLAGS=(--workspace --all-targets --all-features)
      C_TEST_FLAGS=(--workspace)
      ;;
    parcel)
      C_REPO=$(default_repo parcel)
      C_CRATE=.
      C_KIND=informational
      C_CLIPPY_FLAGS=(--workspace --all-targets --all-features)
      C_TEST_FLAGS=(--workspace)
      ;;
  esac
  C_CLIPPY_FLAGS+=(${EXTRA[@]+"${EXTRA[@]}"})
  C_TEST_FLAGS+=(${EXTRA[@]+"${EXTRA[@]}"})
  feature_flags "${C_CLIPPY_FLAGS[@]}" ${C_TEST_FLAGS[@]+"${C_TEST_FLAGS[@]}"}
  var=DOWNSTREAM_${C_UPPER}_REPO
  C_REPO=${!var:-$C_REPO}
  # An empty path would canonicalise to the current directory (often the
  # library itself) and be tested as the consumer.
  [ -n "$C_REPO" ] || die "cannot work out $1's repo path (set DOWNSTREAM_${C_UPPER}_REPO or DOWNSTREAM_PROJECTS)"
  # Once the path-safety check below has pinned the physical path, only that
  # one is used: the given path (a symlink, say) is never looked at again.
  var=pinned_repo_$C_NAME
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
#   postgres:// and postgresql:// URLs (any case), whole, up to a space or a
#   quote  ->  postgres://<redacted>   (a URL with no userinfo and no secret
#   parameter still names a host, a port and a database; the parcel override
#   is the one URL this script itself passes to a consumer)
#   name=value, for a name containing token, password, passwd, secret or key
#   (any case), in a query string or on its own  ->  name=***
# Deliberately blunt: an over-masked line costs a look at the raw run, a leak
# costs a rotation. It is line-buffered so a long build still streams.
REDACT_KEYS='[Tt][Oo][Kk][Ee][Nn]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Kk][Ee][Yy]'
redact() {
  sed -u -E \
    -e "s#[Pp][Oo][Ss][Tt][Gg][Rr][Ee][Ss]([Qq][Ll])?://[^[:space:]\"'<>]*#postgres://<redacted>#g" \
    -e "s#([A-Za-z][A-Za-z0-9+.-]*://)[^[:space:]/\"']*@#\1***@#g" \
    -e "s#(^|[?&;,[:space:]\"'(])([A-Za-z0-9_.-]*($REDACT_KEYS)[A-Za-z0-9_.-]*)=[^&;,[:space:]\"')]*#\1\2=***#g" \
    -e "s#(\"?[A-Za-z0-9_.-]*($REDACT_KEYS)[A-Za-z0-9_.-]*\"?[[:space:]]*:[[:space:]]*(Some\\()?)\"([^\"\\\\]|\\\\.)*\"#\1\"***\"#g"
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
    \[*)
      # A bracketed IPv6 authority: [::1] or [::1]:port. The brackets are
      # dropped; the TCP check wants the bare address.
      host=${a#\[}
      host=${host%%\]*}
      port=${a#*\]}
      case $port in
        '') port=$3 ;;
        :*) port=${port#:} ;;
        *)
          problem "$1: no host and port can be read from its URL ($4)"
          return
          ;;
      esac
      case $host in '' | *[!0-9A-Fa-f:.]*)
        problem "$1: no host can be read from its URL ($4)"
        return
        ;;
      esac
      case $host in *:*) ;; *)
        problem "$1: no host can be read from its URL ($4)"
        return
        ;;
      esac
      ;;
    *:*)
      host=${a%%:*}
      port=${a##*:}
      ;;
    *)
      host=$a
      port=$3
      ;;
  esac
  case $host in '' | *[!A-Za-z0-9._:-]*)
    problem "$1: no host can be read from its URL ($4)"
    return
    ;;
  esac
  case $port in '' | *[!0-9]*)
    problem "$1: no port can be read from its URL ($4)"
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

# lumen's test databases: the caller's LUMEN_RS_TEST_* when set, else lumen's
# own docker compose (lumen-rs has no default, on purpose, so this is it).
# The defaults carry the compose's dev credentials, public in lumen's repo.
LUMEN_DEFAULT_DB_URL='postgres://dev:dev@localhost:55432/lumen_rs_test'
LUMEN_DEFAULT_REDIS_URL='redis://localhost:56379/1'
LUMEN_DEFAULT_GCS_URL='http://localhost:54443'

# Every environment variable NAME lumen-rs reads, unset for the run so nothing
# of the host's reaches a test or the binaries the tests spawn. Derived from
# lumen origin/main (31de3b9) with
#   git grep -h -o -E '"[A-Z][A-Z0-9_]{2,}"' origin/main -- lumen-rs/src lumen-rs/tests lumen-rs/tools
# keeping the names used as lookups (lookup/set/trimmed/read/env::var/.env), the
# LLM_ and TITLE_LLM_ prefixed ones expanded, plus the proxy variables and
# RUST_LOG/PGOPTIONS. Not listed: the three LUMEN_RS_TEST_*_URL (this script sets
# them), PATH, HOME, the CARGO_* and SSL_CERT_* variables the toolchain needs.
LUMEN_UNSET_ENV=(
  DATABASE_URL REDIS_URL LUMEN_RS_DATABASE_URL
  ENVIRONMENT BIND_ADDR FORWARDED_ALLOW_IPS SERVICE_KEY_ALLOWED_USERS INTERNAL_SERVICE_KEY MUSE_KEYWORDS
  LUMEN_HERMETIC LUMEN_FAKES LUMEN_MIGRATIONS_DIR LUMEN_DEV_LOGIN LUMEN_DEV_LOGIN_EMAIL
  LUMEN_CAPS_CHILD CAPS_CHILD_SESSIONS_DONE
  LUMEN_RS_UPDATE_SCHEMA_SNAPSHOT LUMEN_RS_GCS_LIVE LUMEN_RS_GCS_REAL_BUCKET LUMEN_RS_LIVE_ENV_FILE
  GCS_BUCKET GOOGLE_CREDENTIALS STORAGE_EMULATOR_HOST
  IMAGE_GOOGLE_LOCATION IMAGE_GOOGLE_PROJECT IMAGE_MODEL VERTEX_BASE_URL
  LLM_PROVIDER LLM_MODEL LLM_BASE_URL LLM_FIREWORKS_API_KEY LLM_GOOGLE_CREDENTIALS
  TITLE_LLM_PROVIDER TITLE_LLM_MODEL TITLE_LLM_BASE_URL TITLE_LLM_FIREWORKS_API_KEY TITLE_LLM_GOOGLE_CREDENTIALS
  FIREWORKS_API_KEY INWORLD_API_KEY INWORLD_BASE_URL META_API_KEY META_WS_URL
  PERPLEXITY_API_KEY PERPLEXITY_BASE_URL OPEN_METEO_BASE_URL
  VOICE_LIVE_WAV VOICE_LIVE_ACK_TIMEOUT_SECS
  WORKOS_API_BASE_URL WORKOS_API_KEY WORKOS_CLIENT_ID WORKOS_ISSUER WORKOS_ISSUER_ACK
  WORKOS_JWKS_CACHE_SECONDS WORKOS_JWKS_URL
  RUST_LOG PGOPTIONS
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
)

# parcel's DOWNSTREAM_PARCEL_DATABASE_URL (C_DB_URL), when given, is held to
# three rules, each refusal naming the rule and never the value:
#   - a postgres:// or postgresql:// URL (the schemes sqlx reads);
#   - it names a database, and not `parcel`, which is parcel's DEV database
#     (.env.example): the test harness creates schemas in the database it is given
#     and drops the old ones it finds there, so only a throwaway database is safe
#     (the default, parcel_test, is the one the harness creates itself);
#   - its query sets none of host, hostaddr, port or dbname, which sqlx applies
#     over the authority and the path, so the endpoint and database preflight
#     checks (the authority and the path) are always the ones sqlx uses. Percent-
#     encoding in the database name or a parameter name is refused for the same
#     reason (it could spell what the rules above compare).
# Returns 0 when there is no override or it passes; adds to PROBLEMS otherwise.
check_parcel_db_url() {
  local u=$C_DB_URL rest query='' path db param name bad=0
  [ -n "$u" ] || return 0
  case $u in
    postgres://* | postgresql://*) ;;
    *)
      problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the scheme rule: it must be a postgres:// or postgresql:// URL"
      return 1
      ;;
  esac
  rest=${u#*://}
  rest=${rest%%#*}
  case $rest in
    *\?*)
      query=${rest#*\?}
      rest=${rest%%\?*}
      ;;
  esac
  case $rest in
    */*) path=${rest#*/} ;;
    *) path='' ;;
  esac
  db=${path%%/*}
  if [ -z "$db" ]; then
    problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the database rule: it must name a database (not parcel's dev database)"
    bad=1
  else
    case $db in
      *%*)
        problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the database rule: percent-encoding in the database name is not accepted"
        bad=1
        ;;
      parcel)
        problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the database rule: 'parcel' is parcel's dev database; the tests create and drop schemas in the database they are given (name a throwaway one, e.g. parcel_test)"
        bad=1
        ;;
    esac
  fi
  while [ -n "$query" ]; do
    param=${query%%&*}
    case $query in *\&*) query=${query#*&} ;; *) query='' ;; esac
    name=${param%%=*}
    case $name in
      *%*)
        problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the query rule: percent-encoding in a parameter name is not accepted"
        bad=1
        ;;
      host | hostaddr | port | dbname)
        problem "DOWNSTREAM_PARCEL_DATABASE_URL breaks the query rule: host, hostaddr, port and dbname are not accepted (sqlx applies them over the URL's own, so preflight would check another endpoint)"
        bad=1
        ;;
    esac
  done
  [ "$bad" = 0 ]
}

# Everything a consumer needs before a build is worth starting. Fills PROBLEMS.
preflight() {
  PROBLEMS=()
  [ -d "$C_REPO/.git" ] || [ -f "$C_REPO/.git" ] || problem "$C_REPO is not a git repository (set DOWNSTREAM_${C_UPPER}_REPO)"
  [ -n "$C_SHA" ] || problem "ref '$C_REF' does not resolve in $C_REPO (this script does not fetch)"
  if [ -n "$C_SHA" ] && ! git -C "$C_REPO" cat-file -e "$C_SHA:${C_CRATE#./}/Cargo.toml" 2>/dev/null &&
    ! { [ "$C_CRATE" = . ] && git -C "$C_REPO" cat-file -e "$C_SHA:Cargo.toml" 2>/dev/null; }; then
    problem "ref '$C_REF' of $C_NAME has no $C_CRATE/Cargo.toml (set DOWNSTREAM_${C_UPPER}_REF to a ref that has it)"
  fi
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
      if [ -n "${TAPPER_RS_TEST_GCS_EMULATOR_URL+x}" ]; then
        # Set by the caller: theirs is what the run gets, even when empty (tapper's
        # own tests refuse that loudly, and are the ones to say so).
        if [ -n "$TAPPER_RS_TEST_GCS_EMULATOR_URL" ]; then
          need_url_tcp "TAPPER_RS_TEST_GCS_EMULATOR_URL's fake-gcs-server" "$TAPPER_RS_TEST_GCS_EMULATOR_URL" "$(scheme_port "$TAPPER_RS_TEST_GCS_EMULATOR_URL" 80)" "docker compose up -d fake-gcs-server in tapper"
        fi
      else
        need_tcp "fake-gcs-server" 127.0.0.1 4443 "docker compose up -d fake-gcs-server in tapper"
      fi
      ;;
    slauth)
      need_cmd uv
      need_default_postgres 5433 "docker compose up -d postgres in slauth"
      ;;
    spendwise)
      need_default_postgres 5437 "docker compose up -d in spendwise-rs; this script does not provision it"
      ;;
    lumen)
      local lhint="docker compose up -d postgres redis in lumen" lredis=${LUMEN_RS_TEST_REDIS_URL:-$LUMEN_DEFAULT_REDIS_URL}
      need_url_tcp "LUMEN_RS_TEST_DATABASE_URL's Postgres" "${LUMEN_RS_TEST_DATABASE_URL:-$LUMEN_DEFAULT_DB_URL}" 5432 "$lhint"
      case $(redis_db "$lredis") in
        invalid) problem "LUMEN_RS_TEST_REDIS_URL's database is not a number; use another number than 0, e.g. .../1" ;;
        0) problem "LUMEN_RS_TEST_REDIS_URL selects Redis DB 0, which is the dev stack's; use another number, e.g. .../1" ;;
      esac
      need_url_tcp "LUMEN_RS_TEST_REDIS_URL's Redis" "$lredis" 6379 "$lhint"
      lgcs=${LUMEN_RS_TEST_GCS_URL:-$LUMEN_DEFAULT_GCS_URL}
      need_url_tcp "LUMEN_RS_TEST_GCS_URL's fake-gcs-server" "$lgcs" "$(scheme_port "$lgcs" 80)" "docker compose up -d fake-gcs in lumen"
      ;;
    parcel)
      # Neither has a variable of its own: its tests dial these addresses (the
      # Postgres unless DOWNSTREAM_PARCEL_DATABASE_URL names another, which is
      # passed to the run as DATABASE_URL). 5439 may be this library's own
      # Postgres (see the header): a reachable port proves nothing about whose.
      if check_parcel_db_url; then
        need_default_postgres 5439 "docker compose up -d in parcel; not this library's Postgres if it was moved to 5439"
      fi
      need_tcp "parcel's fake-gcs-server" localhost 4447 "docker compose up -d fake-gcs in parcel"
      ;;
    slaudio)
      local hint="docker compose up -d postgres redis in slaudio"
      if [ -n "${SLAUDIO_TEST_DATABASE_URL:-}" ]; then
        need_url_tcp "SLAUDIO_TEST_DATABASE_URL's Postgres" "$SLAUDIO_TEST_DATABASE_URL" 5432 "$hint"
      else
        need_tcp "the slaudio test Postgres" localhost 5435 "$hint"
      fi
      if [ -n "${SLAUDIO_TEST_REDIS_URL:-}" ]; then
        need_url_tcp "SLAUDIO_TEST_REDIS_URL's Redis" "$SLAUDIO_TEST_REDIS_URL" 6379 "$hint"
      else
        need_tcp "the slaudio test Redis" localhost 6381 "$hint"
      fi
      # The schedule tests (once on the ref) read the HOST tz database and fail
      # below 2024b; until then an old host database is only worth a note.
      if ref_has backend-rs/crates/slaudio-core/src/schedule/tests; then
        require_tzdata 2024b
      fi
      note_tzdata 2026c
      # The worker's Restate matrix tests (once on the ref) need the local
      # Restate server from slaudio's docker-compose.yml.
      if ref_has backend-rs/crates/slaudio-worker/tests/scheduler_restate.rs; then
        hint="docker compose up -d restate in slaudio"
        if [ -n "${SLAUDIO_TEST_RESTATE_ADMIN_URL:-}" ]; then
          need_url_tcp "SLAUDIO_TEST_RESTATE_ADMIN_URL's Restate" "$SLAUDIO_TEST_RESTATE_ADMIN_URL" "$(scheme_port "$SLAUDIO_TEST_RESTATE_ADMIN_URL" 9070)" "$hint"
        else
          need_tcp "the slaudio test Restate admin" localhost 9070 "$hint"
        fi
        # Ingress defaults to 8088: slaudio's compose publishes 8088:8080 and its
        # test harness dials localhost:8088 (tests/common/restate.rs).
        if [ -n "${SLAUDIO_TEST_RESTATE_INGRESS_URL:-}" ]; then
          need_url_tcp "SLAUDIO_TEST_RESTATE_INGRESS_URL's Restate" "$SLAUDIO_TEST_RESTATE_INGRESS_URL" "$(scheme_port "$SLAUDIO_TEST_RESTATE_INGRESS_URL" 8088)" "$hint"
        else
          need_tcp "the slaudio test Restate ingress" localhost 8088 "$hint"
        fi
      fi
      ;;
  esac
}

# The port a URL implies when it names none: 80 for http, 443 for https, else
# the given fallback. need_url_tcp uses it only when the URL has no port.
scheme_port() { # url fallback
  case $1 in
    http://*) printf 80 ;;
    https://*) printf 443 ;;
    *) printf '%s' "$2" ;;
  esac
}

# True when the consumer's ref holds the given path (file or directory).
ref_has() { # path-in-repo
  [ -n "$C_SHA" ] && git -C "$C_REPO" cat-file -e "$C_SHA:$1" 2>/dev/null
}

# The host tz database's version (TZDIR, else /usr/share/zoneinfo): the first
# `# version` line of tzdata.zi (any line, surrounding whitespace and CR
# trimmed), else, unless the argument is `zi-only`, +VERSION (macOS). Prints it
# when it looks like a tz release (`2026c`), nothing otherwise.
tzdata_version() { # [zi-only]
  local dir=${TZDIR:-/usr/share/zoneinfo} v=''
  if [ -r "$dir/tzdata.zi" ]; then
    v=$(sed -n 's/^#[[:space:]]\{1,\}version[[:space:]]\{1,\}//p' "$dir/tzdata.zi" | head -n 1 | sed 's/[[:space:]]*$//')
  elif [ "${1:-}" != zi-only ] && [ -r "$dir/+VERSION" ]; then
    v=$(head -n 1 "$dir/+VERSION" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  fi
  case $v in [0-9][0-9][0-9][0-9][a-z]) printf '%s' "$v" ;; esac
}

# True when tz release $1 sorts before $2 (`2025b` < `2026c`), compared
# bytewise: [[ < ]] collates by the current locale, so pin it to C. Both are
# already validated as four digits and one lowercase letter by tzdata_version.
tz_older() ( # a b
  LC_ALL=C
  [[ $1 < $2 ]]
)

# A refusal: the consumer's tests read the host tz database and fail below this
# release. Only tzdata.zi counts here, because that is the version the
# consumer's own reader sees (slaudio has no +VERSION fallback).
require_tzdata() { # minimum
  local v
  v=$(tzdata_version zi-only)
  if [ -z "$v" ]; then
    problem "cannot read the tz database version under ${TZDIR:-/usr/share/zoneinfo}; $C_NAME's tests need $1 or later (point TZDIR at a tz database)"
  elif tz_older "$v" "$1"; then
    problem "the tz database under ${TZDIR:-/usr/share/zoneinfo} is $v; $C_NAME's tests need $1 or later (point TZDIR at a current copy)"
  fi
}

# A NOTE, never a refusal: the host tz database is older than the release the
# consumer's fixtures were cut from. Tests that bring their own synthetic
# database still run, so an old host one must not suppress the suite; it is
# worth knowing when a tz-dependent test then fails.
note_tzdata() { # minimum
  local v
  v=$(tzdata_version)
  if [ -z "$v" ]; then
    printf '%s: note: cannot read the tz database version under %s\n' "$C_NAME" "${TZDIR:-/usr/share/zoneinfo}" >&2
  elif tz_older "$v" "$1"; then
    printf '%s: note: the tz database under %s is %s, older than %s; a tz-dependent test failure may be the host, not the library (point TZDIR at a current copy)\n' "$C_NAME" "${TZDIR:-/usr/share/zoneinfo}" "$v" "$1" >&2
  fi
}

# The environment a consumer's cargo runs in: CARGO_TARGET_DIR, plus whatever
# keeps its tests off databases that are not theirs. RUN_UNSET holds `-u NAME`
# pairs for env(1). Sets RUN_ENV and RUN_UNSET.
build_env() {
  local v pfx
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
      # The emulator tapper's GCS suites dial (tapper plan 017 C-3 reads it,
      # loopback only, no default of its own): the caller's when set, else the
      # compose fake-gcs-server. A ref that does not read it yet ignores it.
      # Set-but-empty is the caller's too (`+x`, not `:-`).
      if [ -n "${TAPPER_RS_TEST_GCS_EMULATOR_URL+x}" ]; then
        RUN_ENV+=("TAPPER_RS_TEST_GCS_EMULATOR_URL=$TAPPER_RS_TEST_GCS_EMULATOR_URL")
      else
        RUN_ENV+=("TAPPER_RS_TEST_GCS_EMULATOR_URL=http://127.0.0.1:4443")
      fi
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
    imgmcp)
      # Hermetic tests; keep another service's ambient URLs out regardless.
      RUN_UNSET+=(-u DATABASE_URL -u REDIS_URL)
      ;;
    slaudio)
      # Its tests read only SLAUDIO_TEST_* (inherited as set, or their own
      # defaults) and never DATABASE_URL or REDIS_URL; unset those anyway.
      RUN_UNSET+=(-u DATABASE_URL -u REDIS_URL)
      ;;
    lumen)
      # The test URLs are passed explicitly (their defaults live in this script);
      # none of the service's own settings is inherited, so a production URL or
      # key in this shell cannot reach a test or the binaries the tests spawn.
      RUN_ENV+=("LUMEN_RS_TEST_DATABASE_URL=${LUMEN_RS_TEST_DATABASE_URL:-$LUMEN_DEFAULT_DB_URL}"
        "LUMEN_RS_TEST_REDIS_URL=${LUMEN_RS_TEST_REDIS_URL:-$LUMEN_DEFAULT_REDIS_URL}"
        "LUMEN_RS_TEST_GCS_URL=${LUMEN_RS_TEST_GCS_URL:-$LUMEN_DEFAULT_GCS_URL}")
      for v in "${LUMEN_UNSET_ENV[@]}"; do RUN_UNSET+=(-u "$v"); done
      ;;
    parcel)
      # Its tests read only DATABASE_URL (a loopback URL, else their own compose
      # default) and fixed local addresses: the explicit override or nothing.
      RUN_UNSET+=(-u DATABASE_URL)
      for v in "${PARCEL_UNSET_ENV[@]}"; do RUN_UNSET+=(-u "$v"); done
      for v in $(compgen -e); do
        for pfx in $PARCEL_UNSET_PREFIXES; do
          case $v in "$pfx"*) RUN_UNSET+=(-u "$v") ;; esac
        done
      done
      if [ -n "$C_DB_URL" ]; then
        RUN_ENV+=("DATABASE_URL=$C_DB_URL")
      fi
      ;;
  esac
}

# The environment variables parcel's tests or the binaries they spawn can read,
# unset for the run so nothing of the host's reaches them. Parcel builds its
# provider settings' names at run time (AUTH_<PROVIDER-ID>_ISSUER, _CLIENT_SECRET,
# _SCOPES, ..., config.rs), so those are unset by PREFIX: every exported name
# starting AUTH_, SLAUTH_, GCS_, BLOB_ or PARCEL_ (build_env enumerates them with
# `compgen -e`, which bash 3.2 has). PARCEL_UNSET_ENV is the rest, by name: the
# server's other settings (config.rs, .env.example), the Google settings of its
# blob store, the proxy variables and RUST_LOG/PGOPTIONS. Not listed: DATABASE_URL
# (handled in build_env: the override or nothing), PATH, HOME, the CARGO_* and
# SSL_CERT_* variables the toolchain needs.
PARCEL_UNSET_PREFIXES='AUTH_ SLAUTH_ GCS_ BLOB_ PARCEL_'
PARCEL_UNSET_ENV=(
  STORAGE_EMULATOR_HOST GOOGLE_CREDENTIALS
  APP_ENV BIND_ADDR PORT LOG_FORMAT RUN_MIGRATIONS
  DEV_AUTH_EMAIL DEV_AUTH_NAME
  RUST_LOG PGOPTIONS
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
)

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
  local root lock n
  local names=()
  # The lock cargo resolves this crate against is its workspace root's
  # (spendwise keeps backend/ as a member of a root workspace), so ask cargo
  # rather than taking the nearest Cargo.lock: one that merely sits in a
  # parent directory belongs to some other workspace.
  if ! root=$(cargo_in_crate locate-project --workspace --message-format plain 2>/dev/null); then
    echo "!! cargo cannot locate $C_NAME's workspace from $C_CRATE_DIR"
    return 1
  fi
  lock=$(dirname "$root")/Cargo.lock
  case $lock in
    "$C_DIR"/*) ;;
    *)
      echo "!! $C_NAME's workspace root is outside its archive"
      return 1
      ;;
  esac
  if [ ! -f "$lock" ]; then
    echo "!! $C_NAME has no Cargo.lock at its workspace root"
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
  local err rc
  local pkgs name version source manifest dir seen=0 bad=0
  # The raw JSON exists only while jq reads it, in a mktemp file (mode 600, a
  # name nobody can have planted a symlink at) that `cleanup` also removes if a
  # signal ends the run first. stderr never touches the disk raw: what lands in
  # a log is masked.
  META_TMP=$(mktemp "$LOGS/$C_NAME-metadata.XXXXXX") || {
    echo "!! cannot create a temporary file in $LOGS"
    return 1
  }
  err=$(cargo_in_crate metadata --format-version 1 ${C_FEATURE_FLAGS[@]+"${C_FEATURE_FLAGS[@]}"} "${PATCH[@]}" 2>&1 >"$META_TMP")
  rc=$?
  printf '%s\n' "$err" | redact >"$LOGS/$C_NAME-metadata.log"
  if [ "$rc" -ne 0 ]; then
    rm -f -- "$META_TMP"
    META_TMP=''
    echo "!! cargo metadata failed:"
    printf '%s\n' "$err" | redact
    return 1
  fi
  pkgs=$(jq -r '.packages[] | select(.name | startswith("stridelabs-"))
    | [.name, .version, (.source // "path"), .manifest_path] | @tsv' "$META_TMP" | sort)
  rc=$?
  rm -f -- "$META_TMP"
  META_TMP=''
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
  # The repo is only ever read from its pinned physical path; if that path now
  # leads somewhere else (swapped for a symlink, say) or into $WORK, the
  # removal below could delete the thing about to be archived.
  if [ "$(canon "$C_REPO")" != "$C_REPO" ] || nested "$C_REPO" "$WORK"; then
    echo "!! refusing to archive $C_REPO: it no longer resolves to itself outside $WORK"
    return 1
  fi
  rm -rf -- "${C_DIR:?}"
  mkdir -p -- "$C_DIR" || return 1
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
mode    : PATCHED development check. Every stridelabs-* crate is [patch]ed to the
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
for c in $KNOWN_CONSUMERS; do
  printf -v "pinned_repo_$c" '%s' '' # nothing inherited from the environment
done
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
  # Pin the repo's physical path: every later load_consumer reads it back.
  if real=$(canon "$C_REPO"); then
    printf -v "pinned_repo_$c" '%s' "$real"
    C_REPO=$real
  else
    path_problem "cannot resolve $c's repo path $C_REPO"
  fi
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
mkdir -p -- "$WORK" || die "cannot create $WORK"
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
# On any exit, INT and TERM included (they exit through this trap): release the
# lock and drop the metadata temp file if a signal arrived while it was on disk.
META_TMP=''
cleanup() {
  [ -z "$META_TMP" ] || rm -f -- "$META_TMP"
  rm -rf -- "$LOCK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Fresh logs, under the lock: whatever a previous run or anyone else left in the
# directory (a symlink at a log's name, or at the directory's) is removed, not
# written through. rm -rf on a symlink removes the link, not what it points at.
rm -rf -- "${LOGS:?}"
mkdir -m 700 -- "$LOGS" || die "cannot create $LOGS"

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
