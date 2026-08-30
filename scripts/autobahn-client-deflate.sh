#!/usr/bin/env bash
# The Autobahn client suite with permessage-deflate negotiated.
#
# A sibling of autobahn-client.sh rather than a flag on it, for the reason the examples are
# siblings: the feature-off arm keeps measuring a byte-identical object.
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
RESULTS='autobahn/client/index.json'
SPEC='autobahn/fuzzingserver.json'
READY_TIMEOUT_SECONDS=30

CONTAINER_ID=''
TESTER_NAME="autobahn-deflate-client-$$"
function cleanup() {
    # One line on purpose: `local` is a command, so declaring first would overwrite `$?`.
    local status=$?
    trap - TERM INT EXIT
    if [ -n "${CONTAINER_ID}" ]; then
        docker container stop "${CONTAINER_ID}" >/dev/null || true
    fi
    exit "${status}"
}
trap cleanup TERM INT EXIT

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
    echo "${TESTER_HOST}:${TESTER_PORT} is already accepting; refusing to publish over it" >&2
    exit 69
fi

CONTAINER_ID=$(docker run -d --rm \
    --name "${TESTER_NAME}" \
    --platform linux/amd64 \
    -v "${PWD}/autobahn:/autobahn" \
    -p 9001:9001 \
    --init \
    "${IMAGE}" \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json')
echo "tester: container ${CONTAINER_ID} named ${TESTER_NAME}"

await_tester_ready

echo 'role: client starting'
cargo run --release --features deflate --example autobahn-client-deflate
echo 'role: client example exited 0'

verify_index
test_diff
