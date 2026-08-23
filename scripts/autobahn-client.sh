#!/usr/bin/env bash
# Author michael <themichaeleden@gmail.com>
set -euo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

# Both roles compare against one oracle, so both must read it through one tester
# build. The mutable tag would let the instrument change between them.
IMAGE=crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074
CONTAINER_NAME=fuzzingserver

# Stop only the container this invocation created. Stopping by name would end
# whatever holds the name, and the case where the name is already held is
# exactly the case where it is not ours.
#
# `|| true` because errexit stays in force inside an EXIT trap: a stop that fails
# would abort the trap and exit 1, discarding the 64 or 65 that says whether this
# run disagreed with the oracle or never finished.
function cleanup() {
    if [ -n "${CONTAINER_ID:-}" ]; then
        docker container stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    return 0
}
trap cleanup TERM EXIT

# `diff <(jq …) <(jq …)` cannot fail closed by itself: process substitution
# discards jq's exit status, so a missing or malformed index reaches `diff` as an
# empty stream, and two empty streams compare equal. An aborted suite is exactly
# that case — it leaves behind a partial index, or none at all.
function check_index() {
    local index=$1 produced expected
    if ! produced=$(jq -e -S '.Tungstenite | keys' "${index}"); then
        echo "${index}: missing, empty, or not valid Autobahn output"
        exit 65
    fi
    expected=$(jq -e -S '.Tungstenite | keys' 'autobahn/expected-results.json')
    if [ "${produced}" != "${expected}" ]; then
        echo "${index}: produced $(jq length <<<"${produced}") cases against the" \
             "oracle's $(jq length <<<"${expected}"); a partial run must not be diffed."
        exit 65
    fi
}

function test_diff() {
    check_index 'autobahn/client/index.json'
    if ! diff -q \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' 'autobahn/expected-results.json') \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' 'autobahn/client/index.json')
    then
        echo 'Difference in results, either this is a regression or' \
             'one should update autobahn/expected-results.json with the new results.'
        exit 64
    fi
}

# No `--rm`: a container that died is the only record of why, and the run that
# needs that record is the one that cannot ask for it afterwards.
CONTAINER_ID=$(docker run -d \
    -v "${PWD}/autobahn:/autobahn" \
    -p 9001:9001 \
    --init \
    --name "${CONTAINER_NAME}" \
    "${IMAGE}" \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json')

sleep 3
cargo run --release --example autobahn-client --features=deflate
test_diff

# Past the diff nothing is left to learn from the tester, and the server role
# that runs next requires this name to be free.
docker container stop "${CONTAINER_ID}" >/dev/null
docker container rm "${CONTAINER_ID}" >/dev/null
CONTAINER_ID=
