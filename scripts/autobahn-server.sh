#!/usr/bin/env bash
# Author michael <themichaeleden@gmail.com>
set -euo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

# Digest-pinned: the tester's own memory growth is what this harness contains, so
# the tester must not change underneath it.
IMAGE=crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074
ORACLE=autobahn/expected-results.json
MANIFEST=autobahn/server-shards.txt
OUTDIR=autobahn/server
SERVER=target/release/examples/autobahn-server
PORT=9002
# A hung shard costs this instead of the job's six-hour default. The watchdog
# signals the docker client only, so the container stays inspectable afterwards.
SHARD_TIMEOUT=${SHARD_TIMEOUT:-600}
# Far above the ~1 GiB a nine-case shard is sized for and below the 6 GiB that has
# killed a monolithic run: a runaway fails its own shard instead of the host.
SHARD_MEMORY=${SHARD_MEMORY:-4g}
# The example server installs no signal handler, so TERM ends it; this bounds the
# case where that stops being true.
SHUTDOWN_GRACE=${SHUTDOWN_GRACE:-10}
# Only ever our own children. A container left behind by a failed shard is
# evidence, and anything else on this host belongs to someone else.
#
# `|| true` is load-bearing rather than defensive: errexit stays in force inside
# an EXIT trap, so signalling an already-reaped PID aborts the trap and the shell
# exits 1. That replaces the code naming the failure -- 70 for an ownership
# change, 65 for an incomplete arm, 64 for an oracle mismatch -- with a bare 1,
# and the server-is-gone path is exactly the path whose PID is already reaped.
function cleanup() {
    if [ -n "${WSSERVER_PID:-}" ]; then kill "${WSSERVER_PID}" 2>/dev/null || true; fi
    if [ -n "${WATCHDOG_PID:-}" ]; then kill "${WATCHDOG_PID}" 2>/dev/null || true; fi
    return 0
}
trap cleanup TERM EXIT

function require_tools() {
    local tool
    for tool in docker jq lsof pgrep; do
        command -v "${tool}" >/dev/null 2>&1 && continue
        echo "${tool} is required: the port-ownership and index checks below are not optional"
        exit 69
    done
}

function listener_pids() {
    lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true
}

# Refuse a dirty host rather than reclaiming it: whatever is holding these ports,
# containers or directories belongs to a run we cannot see. Only this role's own
# output directory, though -- autobahn/client is where the client role that ran
# before us in the same job left the evidence of its pass.
function preflight() {
    local stray port pids
    stray=$(docker ps -a --format '{{.Names}}' | grep -E '^fuzzing(server|client)' || true)
    if [ -n "${stray}" ]; then
        echo "preflight: Autobahn containers present: ${stray}"
        exit 75
    fi
    for port in 9001 "${PORT}"; do
        pids=$(listener_pids "${port}")
        if [ -n "${pids}" ]; then
            echo "preflight: port ${port} is bound by PID(s) ${pids}"
            exit 75
        fi
    done
    stray=$(pgrep -f 'examples/autobahn-(client|server)|wstest -m fuzzing' || true)
    if [ -n "${stray}" ]; then
        echo "preflight: Autobahn processes running: PID(s) ${stray}"
        exit 75
    fi
    if [ -n "$(ls -A "${OUTDIR}" 2>/dev/null)" ]; then
        echo "preflight: ${OUTDIR} is not empty; move it aside instead of overwriting it"
        exit 75
    fi
}

function provenance() {
    echo "=== provenance: $1 ==="
    rustc --version
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        git rev-parse HEAD
        git status --porcelain
        git hash-object scripts/autobahn-server.sh "${MANIFEST}" "${ORACLE}"
    fi
}

function shard_ids() {
    awk '$1 !~ /^#/ && $1 != previous { print $1; previous = $1 }' "${MANIFEST}"
}

function shard_cases() {
    awk -v shard="$1" '$1 == shard { print $2 }' "${MANIFEST}"
}

function case_array() {
    jq -R -s -c 'split("\n") | map(select(length > 0)) | sort'
}

# The manifest is the pre-registered partition, so it -- not the run -- decides
# what gets tested. Drift against the oracle would silently shrink the population.
function verify_manifest() {
    local declared expected ids
    declared=$(awk '$1 !~ /^#/ { print $2 }' "${MANIFEST}" | case_array)
    expected=$(jq -c '.Tungstenite | keys' "${ORACLE}")
    if [ "${declared}" != "${expected}" ]; then
        echo "${MANIFEST}: declared cases differ from ${ORACLE}; the shards no longer partition the suite"
        exit 65
    fi
    ids=$(shard_ids)
    if [ "$(wc -l <<<"${ids}")" != "$(sort -u <<<"${ids}" | wc -l)" ]; then
        echo "${MANIFEST}: a shard's cases are not contiguous, so it would run twice"
        exit 65
    fi
}

# `diff <(jq …) <(jq …)` cannot fail closed by itself: process substitution
# discards jq's exit status, so a missing or malformed index reaches `diff` as an
# empty stream, and two empty streams compare equal. An aborted suite is exactly
# that case -- it leaves behind a partial index, or none at all.
function check_cases() {
    local index=$1 expected=$2 produced
    if ! produced=$(jq -e -c '.Tungstenite | keys' "${index}"); then
        echo "${index}: missing, empty, or not valid Autobahn output"
        exit 65
    fi
    if [ "${produced}" != "${expected}" ]; then
        echo "${index}: produced $(jq length <<<"${produced}") cases against the expected" \
             "$(jq length <<<"${expected}"); a partial run must not be diffed."
        exit 65
    fi
}

function test_diff() {
    check_cases "${OUTDIR}/index.json" "$(jq -c '.Tungstenite | keys' "${ORACLE}")"
    if ! diff -q \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' "${ORACLE}") \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' "${OUTDIR}/index.json")
    then
        echo 'Difference in results, either this is a regression or' \
             'one should update autobahn/expected-results.json with the new results.'
        exit 64
    fi
}

# Build first so the PID we track and re-verify is the server itself: `cargo run &`
# sets $! to the cargo wrapper, which proves nothing about the listener and whose
# death can orphan it.
function start_server() {
    cargo build --release --example autobahn-server --features=deflate
    "./${SERVER}" & WSSERVER_PID=$!
    sleep 3
    verify_server
}

# Every shard trusts that its results came from the server this run started, on the
# port this run owns. A silent restart or a second listener would invalidate that.
function verify_server() {
    local pids command
    if ! kill -0 "${WSSERVER_PID}" 2>/dev/null; then
        echo "server ${WSSERVER_PID} is gone"
        exit 70
    fi
    command=$(ps -o comm= -p "${WSSERVER_PID}" | tr -d ' ')
    case "${command}" in
        *autobahn-server) ;;
        *) echo "PID ${WSSERVER_PID} is '${command}', not the Autobahn server"; exit 70 ;;
    esac
    pids=$(listener_pids "${PORT}")
    if [ "${pids}" != "${WSSERVER_PID}" ]; then
        echo "port ${PORT} is listened on by '${pids}', not by our server ${WSSERVER_PID}"
        exit 70
    fi
}

# Everything above proves the server was ours while it mattered. This proves the
# host is clean afterwards, which is the next run's preflight and not something a
# TERM we never waited on can establish.
function shutdown_server() {
    local pids
    kill "${WSSERVER_PID}" 2>/dev/null || true
    # A bare `wait` is unbounded, and a server that ignores TERM would spend the
    # job's six-hour default on the last step of a run whose results are already
    # collected and diffed. Escalate rather than wait on cooperation.
    ( sleep "${SHUTDOWN_GRACE}"
      kill -0 "${WSSERVER_PID}" 2>/dev/null || exit 0
      echo "server ${WSSERVER_PID} outlived TERM by ${SHUTDOWN_GRACE}s; sending KILL"
      kill -KILL "${WSSERVER_PID}" 2>/dev/null ) & WATCHDOG_PID=$!
    wait "${WSSERVER_PID}" 2>/dev/null || true
    kill "${WATCHDOG_PID}" 2>/dev/null || true
    if kill -0 "${WSSERVER_PID}" 2>/dev/null; then
        echo "server ${WSSERVER_PID} is still running after shutdown"
        exit 70
    fi
    pids=$(listener_pids "${PORT}")
    if [ -n "${pids}" ]; then
        echo "port ${PORT} is still bound by PID(s) ${pids} after shutdown"
        exit 70
    fi
    WSSERVER_PID=
}

function run_shard() {
    local shard=$1 directory container specification status=0
    directory="${OUTDIR}/shard-${shard}"
    container="fuzzingclient-shard-${shard}"
    specification="${directory}/fuzzingclient.json"

    verify_server
    mkdir -p "${directory}"
    shard_cases "${shard}" | jq -R -s --arg outdir "./${directory}" '{
        outdir: $outdir,
        servers: [{ agent: "Tungstenite", url: "ws://127.0.0.1:9002" }],
        cases: (split("\n") | map(select(length > 0))),
        "exclude-cases": [],
        "exclude-agent-cases": {}
    }' > "${specification}"

    # PYTHONUNBUFFERED so a case ID in the log means a case: wstest's stdout
    # otherwise flushes every ~103 cases and the last ID names a buffer boundary.
    docker run --name "${container}" \
        --memory="${SHARD_MEMORY}" \
        -e PYTHONUNBUFFERED=1 \
        -v "${PWD}/autobahn:/autobahn" \
        --network host \
        "${IMAGE}" \
        wstest -m fuzzingclient -s "${specification}" &
    local docker_pid=$!
    ( sleep "${SHARD_TIMEOUT}"; kill -TERM "${docker_pid}" 2>/dev/null ) & WATCHDOG_PID=$!
    wait "${docker_pid}" || status=$?
    kill "${WATCHDOG_PID}" 2>/dev/null || true

    if [ "${status}" -ne 0 ]; then
        echo "shard ${shard}: docker exited ${status} (143 = the ${SHARD_TIMEOUT}s watchdog fired)"
        docker inspect "${container}" --format \
            'Running: {{.State.Running}}  OOMKilled: {{.State.OOMKilled}}  ExitCode: {{.State.ExitCode}}  Error: {{.State.Error}}'
        exit "${status}"
    fi
    check_cases "${directory}/index.json" "$(shard_cases "${shard}" | case_array)"
    verify_server
    docker rm "${container}" >/dev/null
}

# The shards partition the suite, so their union must hold every case exactly once.
# An overlap would let one shard's verdict quietly overwrite another's.
function aggregate() {
    local declared merged shard
    local parts=()
    while read -r shard; do
        parts+=("${OUTDIR}/shard-${shard}/index.json")
    done < <(shard_ids)
    merged=$(jq -s '{ Tungstenite: (map(.Tungstenite) | add) }' "${parts[@]}")
    declared=$(jq -s '[.[].Tungstenite | length] | add' "${parts[@]}")
    printf '%s\n' "${merged}" > "${OUTDIR}/index.json"
    if [ "${declared}" != "$(jq '.Tungstenite | length' "${OUTDIR}/index.json")" ]; then
        echo "${OUTDIR}/index.json: the shards reported ${declared} cases but their union is smaller; they overlap"
        exit 65
    fi
}

require_tools
preflight
provenance start
verify_manifest

start_server
for shard in $(shard_ids); do
    run_shard "${shard}"
done
verify_server

aggregate
test_diff
verify_server
shutdown_server
provenance end
