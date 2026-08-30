#!/usr/bin/env bash
# The Autobahn server suite with permessage-deflate negotiated.
#
# A sibling of autobahn-server.sh rather than a flag on it, for the reason the examples are
# siblings: the feature-off arm keeps measuring a byte-identical object.
#
# No `set -x`: the canonical JSON values below are ~84 KiB each and xtrace would print both.
set -euo pipefail
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

# Pinned by manifest digest rather than the mutable `latest` tag: these 216 compression
# cases are graded now, so which tester produced a result is part of the result.
IMAGE_DIGEST='sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074'
IMAGE_CONFIG_DIGEST='sha256:b0475418d42ae284876bd695f0282fbe6684e00f745d787b095d60e55727a06f'
IMAGE="crossbario/autobahn-testsuite@${IMAGE_DIGEST}"
ORACLE='autobahn/expected-results-deflate.json'
RESULTS='autobahn/server/index.json'
SPEC='autobahn/fuzzingclient.json'
# Must match `READY_MARKER` in examples/autobahn-server-deflate.rs.
READY_MARKER='autobahn-server-deflate: listening on'
READY_TIMEOUT_SECONDS=30

SERVER_BIN=''
SERVER_PID=''
RUN_DIR=''
SERVER_LOG=''
TESTER_CID_FILE=''
CONTAINER_ID=''

function cleanup() {
    # One line on purpose: `local` is a command, so declaring first would overwrite `$?`.
    # TERM and INT supply their own status: a signal to this PID alone, during a command
    # that then succeeds, leaves `$?` at zero, and `${1:-$?}` is what keeps EXIT unaffected.
    local status=${1:-$?}
    trap - TERM INT EXIT
    # From docker's own write, not the assignment below: a signal during `docker create`
    # would never reach it and would leave a container nothing owns.
    if [ -z "${CONTAINER_ID}" ] && [ -n "${TESTER_CID_FILE}" ]; then
        CONTAINER_ID=$(cat "${TESTER_CID_FILE}" 2>/dev/null || true)
    fi
    if [ -n "${CONTAINER_ID}" ]; then
        docker container stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
        # Emitted before removal, from the one site every path reaches: `--rm` would have
        # erased exactly this on the exit-137 path.
        docker container inspect "${CONTAINER_ID}" \
            --format 'tester: terminal ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}' \
            2>/dev/null || true
        docker container rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        # Reaped, not merely signalled, so the script never outlives the listener it owns.
        wait "${SERVER_PID}" 2>/dev/null || true
        echo "cleanup: server child ${SERVER_PID} signalled and reaped"
    fi
    if [ -n "${RUN_DIR}" ]; then
        if [ "${status}" -eq 0 ]; then
            rm -rf "${RUN_DIR}"
        else
            # Display only, never counted: the case verdicts live in the result index.
            if [ -s "${SERVER_LOG}" ]; then
                echo "--- last 50 lines of ${SERVER_LOG} ---" >&2
                tail -n 50 "${SERVER_LOG}" >&2
            fi
            echo "cleanup: run state retained at ${RUN_DIR}" >&2
        fi
    fi
    exit "${status}"
}
trap 'cleanup 143' TERM
trap 'cleanup 130' INT
trap cleanup EXIT

function verify_image() {
    # Asked of the registry, so it checks the pin itself and not whatever the local store
    # happens to hold under that name.
    local config_digest
    config_digest=$(docker manifest inspect "${IMAGE}" | jq -r '.config.digest')
    if [ "${config_digest}" != "${IMAGE_CONFIG_DIGEST}" ]; then
        echo "tester config digest ${config_digest} is not ${IMAGE_CONFIG_DIGEST}" >&2
        exit 65
    fi
    docker pull --platform linux/amd64 --quiet "${IMAGE}" >/dev/null
    local repo_digests
    repo_digests=$(docker image inspect "${IMAGE}" --format '{{json .RepoDigests}}')
    if ! echo "${repo_digests}" |
        jq -e --arg digest "${IMAGE_DIGEST}" 'any(.[]; endswith("@" + $digest))' >/dev/null; then
        echo "resolved RepoDigests ${repo_digests} does not contain ${IMAGE_DIGEST}" >&2
        exit 65
    fi
    # Recorded, never asserted equal to either digest above: a containerd image store
    # reports the manifest digest here and a classic one reports the config digest, so
    # only the registry lookup discriminates. This line is provenance for the log.
    docker image inspect "${IMAGE}" --format 'image: pinned, local .Id {{.Id}}'
}

# From the tester's own spec, so a host collision's address-only relabel stays in one place.
function resolve_endpoint() {
    local url
    url=$(jq -r '.servers[0].url' "${SPEC}")
    local hostport=${url#ws://}
    SERVER_HOST=${hostport%%:*}
    SERVER_PORT=${hostport##*:}
    # `jq -r` prints `null` and exits 0 for a missing key, so the value is checked.
    if [ -z "${SERVER_HOST}" ] || [[ ! "${SERVER_PORT}" =~ ^[0-9]+$ ]]; then
        echo "no usable server endpoint in ${SPEC}: ${url}" >&2
        exit 65
    fi
}

# A connect-and-close probe. The subshell keeps the descriptor from leaking into the run.
function port_accepts() {
    (exec 3<>"/dev/tcp/${SERVER_HOST}/${SERVER_PORT}") 2>/dev/null
}

function await_server_ready() {
    local deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        # Child first: once it is gone an accepting port is a stranger's.
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            echo "readiness: server child ${SERVER_PID} exited before binding" >&2
            exit 66
        fi
        if grep -qF "${READY_MARKER}" "${SERVER_LOG}" && port_accepts; then
            echo "readiness: post-bind marker present, ${SERVER_HOST}:${SERVER_PORT} accepting," \
                 "child ${SERVER_PID} alive"
            return 0
        fi
        sleep 0.2
    done
    echo "readiness: no marker plus accepting port within ${READY_TIMEOUT_SECONDS}s" >&2
    exit 67
}

function verify_index() {
    if ! jq -e 'has("Tungstenite")' "${RESULTS}" >/dev/null; then
        echo 'Result index is unparseable or names no Tungstenite agent.' >&2
        exit 64
    fi
    # Not `diff <(jq …) <(jq …)`: two failing producers yield empty streams it calls identical.
    local oracle_ids results_ids
    oracle_ids=$(jq -S '.Tungstenite | keys' "${ORACLE}")
    results_ids=$(jq -S '.Tungstenite | keys' "${RESULTS}")
    if [ "${oracle_ids}" != "${results_ids}" ]; then
        echo 'Result index does not hold exactly the case IDs the oracle expects.' >&2
        exit 64
    fi
}

function test_diff() {
    # Both sides lose trailing newlines: fine for a semantic gate, and the oracle blob SHA
    # remains the byte anchor.
    local oracle_canonical results_canonical
    oracle_canonical=$(jq -S 'del(."Tungstenite" | .. | .duration?)' "${ORACLE}")
    results_canonical=$(jq -S 'del(."Tungstenite" | .. | .duration?)' "${RESULTS}")
    if [ "${oracle_canonical}" != "${results_canonical}" ]; then
        echo 'Difference in results. A compression case that is not OK is a defect in this' \
             'change; the oracle is pre-registered and is never rewritten from a run.'
        exit 64
    fi
    echo "oracle: exact match on $(jq -r '.Tungstenite | keys | length' "${ORACLE}") cases"
}

verify_image
resolve_endpoint

if port_accepts; then
    echo "${SERVER_HOST}:${SERVER_PORT} is already accepting; refusing to run beside a stranger" >&2
    exit 69
fi

# Launching the binary rather than `cargo run` keeps the retained PID on the listener, so the
# path has to come from somewhere. From cargo's own JSON, not a literal `target/release/...`:
# `CARGO_TARGET_DIR` moves the artifact and the literal then launches an older in-tree build.
function resolve_server_bin() {
    local build_json
    # Synchronous and outside the readiness bound, so a slow cold build cannot read as a
    # slow bind. Only stdout is captured; cargo's progress still goes to the terminal.
    build_json=$(cargo build --release --features deflate \
        --example autobahn-server-deflate --message-format=json)
    local executables
    executables=$(printf '%s\n' "${build_json}" |
        jq -r 'select(.reason == "compiler-artifact")
               | select(.target.name == "autobahn-server-deflate")
               | select(.target.kind | index("example"))
               | .executable | select(. != null)')
    # Asserted, not inferred from the assignment: a zero-match `jq` exits 0 and yields an
    # empty value, so a checked assignment alone would go on to launch the empty string.
    local count
    count=$(printf '%s' "${executables}" | grep -c . || true)
    if [ "${count}" -ne 1 ]; then
        echo "cargo named ${count} example executables for autobahn-server-deflate," \
             'expected exactly 1' >&2
        exit 70
    fi
    SERVER_BIN=${executables}
}

resolve_server_bin
if [ ! -x "${SERVER_BIN}" ]; then
    echo "cargo named ${SERVER_BIN}, which is not executable" >&2
    exit 70
fi
echo "server: launching ${SERVER_BIN}"

# One owned directory: an explicit `XXXXXX` template because `mktemp -t <name>` is BSD-only,
# and it gives the cidfile a path that does not exist yet, which `docker create` requires.
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/autobahn-server-deflate.XXXXXX")
SERVER_LOG="${RUN_DIR}/server.log"
TESTER_CID_FILE="${RUN_DIR}/tester.cid"

"${SERVER_BIN}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
echo "server: pid ${SERVER_PID}, log ${SERVER_LOG}"

await_server_ready

# `create` then `start`, so the ID exists before anything runs. No `--rm`: it deletes the
# container and with it the terminal state an exit 137 is diagnosed from.
docker create --cidfile "${TESTER_CID_FILE}" \
    --platform linux/amd64 \
    -v "${PWD}/autobahn:/autobahn" \
    --network host \
    "${IMAGE}" \
    wstest -m fuzzingclient -s 'autobahn/fuzzingclient.json' >/dev/null
CONTAINER_ID=$(cat "${TESTER_CID_FILE}")
echo "role: server starting, tester container ${CONTAINER_ID}"

TESTER_STATUS=0
docker start --attach "${CONTAINER_ID}" || TESTER_STATUS=$?
if [ "${TESTER_STATUS}" -ne 0 ]; then
    echo "tester exited ${TESTER_STATUS}; see the terminal state below" >&2
    exit "${TESTER_STATUS}"
fi
echo 'role: server tester exited 0'

verify_index
test_diff
