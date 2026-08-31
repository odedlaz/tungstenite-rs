#!/usr/bin/env bash
# The Autobahn client suite with permessage-deflate negotiated.
#
# A sibling of autobahn-client.sh rather than a flag on it, for the reason the examples are
# siblings: the feature-off arm keeps measuring a byte-identical object.
# No `set -x`: the canonical JSON values below are ~84 KiB each and xtrace would print both.
#
# The supervisor below is duplicated in autobahn-server-deflate.sh rather than shared. A common
# library would be a third file and this round is scoped to these two scripts; the duplication
# is deliberate and should be collapsed only together with the sibling examples.
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
RESULTS_DIR='autobahn/client'
RESULTS="${RESULTS_DIR}/index.json"
SPEC='autobahn/fuzzingserver.json'
READY_TIMEOUT_SECONDS=30

RUN_DIR=''
TESTER_CID_FILE=''
CONTAINER_ID=''
WORKLOAD_PID=''
CLEANUP_STATUS=0
PENDING_SIGNAL=''

function cleanup_failed() {
    echo "cleanup: could not $1" >&2
    CLEANUP_STATUS=75
}

function cleanup() {
    # Every caller passes the status, EXIT included, so `$?` is never read here: reading it
    # inside the function makes it the status of whatever the caller last evaluated, which for
    # a call inside an `if` is the condition. Absent means unknown, and unknown fails closed.
    local status=${1:-1}
    trap - TERM INT EXIT
    # From docker's own write, not the assignment below: a signal during `docker create`
    # would never reach it and would leave a container nothing owns.
    if [ -z "${CONTAINER_ID}" ] && [ -n "${TESTER_CID_FILE}" ]; then
        CONTAINER_ID=$(cat "${TESTER_CID_FILE}" 2>/dev/null || true)
    fi
    if [ -n "${WORKLOAD_PID}" ]; then
        if kill "${WORKLOAD_PID}" 2>/dev/null; then
            wait "${WORKLOAD_PID}" 2>/dev/null || true
            echo "cleanup: client child ${WORKLOAD_PID} signalled and reaped"
        elif kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
            cleanup_failed "signal client child ${WORKLOAD_PID}, which is still alive"
        else
            echo "cleanup: client child ${WORKLOAD_PID} had already exited"
        fi
    fi
    if [ -n "${CONTAINER_ID}" ]; then
        docker container stop "${CONTAINER_ID}" >/dev/null 2>&1 ||
            cleanup_failed "stop tester ${CONTAINER_ID}"
        # The terminal state is the only postmortem an exit 137 can be diagnosed from, and
        # `--rm` would have erased it. If reading it fails the container is deliberately kept:
        # removing it here would destroy the evidence this block exists to capture.
        if docker container inspect "${CONTAINER_ID}" \
            --format 'tester: terminal ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}'
        then
            docker container rm "${CONTAINER_ID}" >/dev/null 2>&1 ||
                cleanup_failed "remove tester ${CONTAINER_ID}"
        else
            cleanup_failed "inspect tester ${CONTAINER_ID}; container retained as the postmortem"
        fi
    fi
    # A run whose cleanup cannot account for its own resources has not earned a pass, whatever
    # the case verdicts said. An existing failure is kept: it is the more specific cause.
    if [ "${CLEANUP_STATUS}" -ne 0 ] && [ "${status}" -eq 0 ]; then
        status=${CLEANUP_STATUS}
    fi
    if [ -n "${RUN_DIR}" ]; then
        if [ "${status}" -eq 0 ]; then
            rm -rf "${RUN_DIR}"
        else
            echo "cleanup: run state retained at ${RUN_DIR}" >&2
        fi
    fi
    exit "${status}"
}
trap 'cleanup 143' TERM
trap 'cleanup 130' INT
trap 'cleanup $?' EXIT

# Bash runs a pending trap between commands, so a signal arriving between `&` and the `$!` that
# records the PID would reach a cleanup that cannot see the child it just created. Inside the
# window the handler only records; `resume_signals` re-arms and then acts on whatever arrived.
function defer_signals() {
    trap 'PENDING_SIGNAL=143' TERM
    trap 'PENDING_SIGNAL=130' INT
}

function resume_signals() {
    trap 'cleanup 143' TERM
    trap 'cleanup 130' INT
    if [ -n "${PENDING_SIGNAL}" ]; then
        cleanup "${PENDING_SIGNAL}"
    fi
}

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
    url=$(jq -r '.url' "${SPEC}")
    local hostport=${url#ws://}
    TESTER_HOST=${hostport%%:*}
    TESTER_PORT=${hostport##*:}
    # `jq -r` prints `null` and exits 0 for a missing key, so the value is checked.
    if [ -z "${TESTER_HOST}" ] || [[ ! "${TESTER_PORT}" =~ ^[0-9]+$ ]]; then
        echo "no usable tester endpoint in ${SPEC}: ${url}" >&2
        exit 65
    fi
}

# A connect-and-close probe. The subshell keeps the descriptor from leaking into the run.
function port_accepts() {
    (exec 3<>"/dev/tcp/${TESTER_HOST}/${TESTER_PORT}") 2>/dev/null
}

function await_tester_ready() {
    local deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        # Owned container first: once it is gone, an accepting published port is a stranger's.
        local running
        running=$(docker container inspect -f '{{.State.Running}}' "${CONTAINER_ID}" \
            2>/dev/null || true)
        if [ "${running}" != 'true' ]; then
            echo "readiness: owned tester ${CONTAINER_ID} is not running" >&2
            docker logs "${CONTAINER_ID}" >&2 2>/dev/null || true
            exit 66
        fi
        if port_accepts; then
            echo "readiness: ${TESTER_HOST}:${TESTER_PORT} accepting, owned tester alive"
            return 0
        fi
        sleep 0.2
    done
    echo "readiness: published port not accepting within ${READY_TIMEOUT_SECONDS}s" >&2
    exit 67
}

# The server role refuses to grade unless its tester exited 0. This is that gate for a role whose
# tester is a long-lived server instead of a run-to-completion client: the question is not what it
# exited with but whether it was still alive to serve the suite it is about to be graded on.
# Without it the only thing standing between a dead tester and a verdict is an `.unwrap()` in the
# example -- upstream code, not a guard this harness owns.
function assert_tester_survived() {
    local state
    state=$(docker container inspect "${CONTAINER_ID}" \
        --format '{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}' 2>/dev/null || true)
    if [ -z "${state}" ]; then
        echo "tester ${CONTAINER_ID} could not be inspected after the suite; refusing to grade" >&2
        exit 68
    fi
    if [ "${state%% *}" != 'true' ]; then
        echo "tester ${CONTAINER_ID} did not survive the suite" \
             "(Running ExitCode OOMKilled: ${state}); refusing to grade" >&2
        exit 68
    fi
    echo "tester: alive after the suite (Running ExitCode OOMKilled: ${state})"
}

function verify_index() {
    # The directory was refused if it pre-existed, so an index here was produced by this run.
    # Its absence means the workload never wrote one, which is not something to grade.
    if [ ! -s "${RESULTS}" ]; then
        echo "${RESULTS} was not produced by this run." >&2
        exit 64
    fi
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

# Refused, not deleted: a pre-existing directory is prior evidence and this run has no standing
# to destroy it. Refusing is also what makes freshness unrepresentable rather than merely
# unchecked -- an index present at grading time can only have come from this run.
if [ -e "${RESULTS_DIR}" ]; then
    echo "${RESULTS_DIR} already exists; archive or remove it before running" >&2
    exit 71
fi

verify_image
resolve_endpoint

if port_accepts; then
    echo "${TESTER_HOST}:${TESTER_PORT} is already accepting; refusing to publish over it" >&2
    exit 69
fi

# An explicit `XXXXXX` template (`mktemp -t <name>` is BSD-only), giving the cidfile a path
# that does not exist yet, which `docker create` requires -- it refuses to clobber one.
# The assignment stays bare. `local` and `declare` supply their own exit status, so `set -e`
# would never see a rejected template and the run would continue with an empty `RUN_DIR`.
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/autobahn-client-deflate.XXXXXX")
TESTER_CID_FILE="${RUN_DIR}/tester.cid"

# `create` then `start`, so the ID exists before anything runs. No `--rm`: it deletes the
# container and with it the terminal state an exit 137 is diagnosed from.
docker create --cidfile "${TESTER_CID_FILE}" \
    --platform linux/amd64 \
    -v "${PWD}/autobahn:/autobahn" \
    -p 9001:9001 \
    --init \
    "${IMAGE}" \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json' >/dev/null
CONTAINER_ID=$(cat "${TESTER_CID_FILE}")
docker start "${CONTAINER_ID}" >/dev/null
echo "tester: container ${CONTAINER_ID}"

await_tester_ready

# Backgrounded and waited rather than run in the foreground. Bash defers a trapped signal until
# a foreground external command returns, so a hung suite would sit past the outer 30-minute
# bound and reach SIGKILL with the trap never having run. `wait` is interruptible.
echo 'role: client starting'
defer_signals
cargo run --locked --release --features deflate --example autobahn-client-deflate &
WORKLOAD_PID=$!
resume_signals

CLIENT_STATUS=0
wait "${WORKLOAD_PID}" || CLIENT_STATUS=$?
WORKLOAD_PID=''
if [ "${CLIENT_STATUS}" -ne 0 ]; then
    echo "client example exited ${CLIENT_STATUS}" >&2
    exit "${CLIENT_STATUS}"
fi
echo 'role: client example exited 0'

assert_tester_survived
verify_index
test_diff
