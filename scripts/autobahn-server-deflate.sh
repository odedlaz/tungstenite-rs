#!/usr/bin/env bash
# The Autobahn server suite with permessage-deflate negotiated.
#
# A sibling of autobahn-server.sh rather than a flag on it, for the reason the examples are
# siblings: the feature-off arm keeps measuring a byte-identical object.
#
# No `set -x`: the canonical JSON values below are ~84 KiB each and xtrace would print both.
#
# The supervisor below is duplicated in autobahn-client-deflate.sh rather than shared. A common
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
RESULTS_DIR='autobahn/server'
RESULTS="${RESULTS_DIR}/index.json"
SPEC='autobahn/fuzzingclient.json'
# Must match `READY_MARKER` in examples/autobahn-server-deflate.rs.
READY_MARKER='autobahn-server-deflate: listening on'
READY_TIMEOUT_SECONDS=30

SERVER_BIN=''
SERVER_PID=''
TESTER_WAIT_PID=''
RUN_DIR=''
SERVER_LOG=''
TESTER_CID_FILE=''
CONTAINER_ID=''
CLEANUP_STATUS=0
PENDING_SIGNAL=''

function cleanup_failed() {
    echo "cleanup: could not $1" >&2
    CLEANUP_STATUS=75
}

# The attach helper is a signal-forwarding proxy, not a directly owned child, so the
# TERM-then-wait pattern the Rust children use does not apply to it: `docker start --attach`
# forwards a catchable signal to the container rather than returning, and a hung container then
# keeps the helper attached forever. Cleanup has disarmed its traps by here, and terminal
# inspection, server termination and log retention all sit below, so a graceful stop is
# forbidden -- SIGKILL cannot be caught or proxied.
function collect_helper() {
    local pid=$1
    if kill -0 "${pid}" 2>/dev/null; then
        # The test is whether the signal could be *delivered*, not whether the PID is still
        # visible afterwards: a killed child is a zombie until `wait` reaps it, and `kill -0`
        # succeeds on a zombie. Polling liveness here would report every successful kill as a
        # cleanup failure and promote a clean run to nonzero.
        if ! kill -9 "${pid}" 2>/dev/null && kill -0 "${pid}" 2>/dev/null; then
            cleanup_failed "kill attach helper ${pid}, which is still alive"
            return 0
        fi
        echo "cleanup: attach helper ${pid} was still attached and took SIGKILL"
    fi
    # Reached only once the helper is gone or has taken an uncatchable kill, so it cannot block.
    # A nonzero status here is evidence of how it was collected, not a workload failure.
    wait "${pid}" 2>/dev/null || true
    echo "cleanup: attach helper ${pid} collected"
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
    # Stopped before the helper is collected, because that is what makes the helper return.
    # `docker start --attach` forwards signals rather than exiting on them, so a TERM aimed at
    # the helper reaches the container instead, and a hung container keeps the helper attached.
    if [ -n "${CONTAINER_ID}" ]; then
        docker container stop "${CONTAINER_ID}" >/dev/null 2>&1 ||
            cleanup_failed "stop tester ${CONTAINER_ID}"
    fi
    if [ -n "${TESTER_WAIT_PID}" ]; then
        collect_helper "${TESTER_WAIT_PID}"
    fi
    if [ -n "${CONTAINER_ID}" ]; then
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
    if [ -n "${SERVER_PID}" ]; then
        # `wait` holds the only authoritative status for this child, and nothing outside the
        # script can recover it: a wrapper is the script's parent, not the listener's. Which
        # branch reaped it decides whether it counts. A status cleanup itself provoked must not
        # overwrite the workload result that brought us here; one from a child that died
        # unprompted is the run's own failure, and under direct CI no wrapper remains to
        # adjudicate it.
        local server_status=0
        if kill "${SERVER_PID}" 2>/dev/null; then
            # Reaped, not merely signalled, so the script never outlives the listener it owns.
            wait "${SERVER_PID}" 2>/dev/null || server_status=$?
            echo "cleanup: server child ${SERVER_PID} signalled and reaped," \
                 "wait status ${server_status}"
        elif kill -0 "${SERVER_PID}" 2>/dev/null; then
            cleanup_failed "signal server child ${SERVER_PID}, which is still alive"
        else
            # The informative case: a child that died on its own is still waitable, so its real
            # exit code survives here. Without this the crash path reports no status at all.
            wait "${SERVER_PID}" 2>/dev/null || server_status=$?
            echo "cleanup: server child ${SERVER_PID} had already exited," \
                 "wait status ${server_status}"
            # An existing failure is kept: it is the more specific cause.
            if [ "${server_status}" -ne 0 ] && [ "${status}" -eq 0 ]; then
                status=${server_status}
            fi
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
    # `--locked` so the resolution recorded around this role is the one it builds against:
    # the lock is not committed and flate2 is range-resolved, so an unlocked build could
    # silently pick a different version than the one the run reports.
    build_json=$(cargo build --locked --release --features deflate \
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
# The assignment stays bare. `local` and `declare` supply their own exit status, so `set -e`
# would never see a rejected template and the run would continue with an empty `RUN_DIR`.
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/autobahn-server-deflate.XXXXXX")
SERVER_LOG="${RUN_DIR}/server.log"
TESTER_CID_FILE="${RUN_DIR}/tester.cid"

defer_signals
"${SERVER_BIN}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
resume_signals
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

# Backgrounded and waited rather than run in the foreground. Bash defers a trapped signal until
# a foreground external command returns, so a hung tester would sit past the outer 30-minute
# bound and reach SIGKILL with the trap never having run. `wait` is interruptible.
defer_signals
docker start --attach "${CONTAINER_ID}" &
TESTER_WAIT_PID=$!
resume_signals

TESTER_STATUS=0
wait "${TESTER_WAIT_PID}" || TESTER_STATUS=$?
TESTER_WAIT_PID=''
if [ "${TESTER_STATUS}" -ne 0 ]; then
    echo "tester exited ${TESTER_STATUS}; see the terminal state below" >&2
    exit "${TESTER_STATUS}"
fi
echo 'role: server tester exited 0'

verify_index
test_diff
