#!/usr/bin/env bash
# The Autobahn server suite with permessage-deflate negotiated.
#
# A sibling of autobahn-server.sh rather than a flag on it, for the reason the examples are
# siblings: the feature-off arm keeps measuring a byte-identical object.
set -euo pipefail
set -x
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

WSSERVER_PID=''
function cleanup() {
    status=$?
    if [ -n "${WSSERVER_PID}" ]; then
        kill -9 "${WSSERVER_PID}" || true
    fi
    exit "${status}"
}
trap cleanup TERM EXIT

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
    docker image inspect "${IMAGE}" --format 'local image .Id {{.Id}}'
}

function verify_index() {
    if ! jq -e 'has("Tungstenite")' "${RESULTS}" >/dev/null; then
        echo 'Result index is unparseable or names no Tungstenite agent.' >&2
        exit 64
    fi
    if ! diff -q \
        <(jq -S '.Tungstenite | keys' "${ORACLE}") \
        <(jq -S '.Tungstenite | keys' "${RESULTS}"); then
        echo 'Result index does not hold exactly the case IDs the oracle expects.' >&2
        exit 64
    fi
}

function test_diff() {
    if ! diff -q \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' "${ORACLE}") \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' "${RESULTS}"); then
        echo 'Difference in results. A compression case that is not OK is a defect in this' \
             'change; the oracle is pre-registered and is never rewritten from a run.'
        exit 64
    fi
}

verify_image

cargo run --release --features deflate --example autobahn-server-deflate & WSSERVER_PID=$!
sleep 3

docker run --rm \
    --platform linux/amd64 \
    -v "${PWD}/autobahn:/autobahn" \
    --network host \
    "${IMAGE}" \
    wstest -m fuzzingclient -s 'autobahn/fuzzingclient.json'

verify_index
test_diff
