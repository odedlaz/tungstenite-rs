#!/usr/bin/env bash
# Author michael <themichaeleden@gmail.com>
set -euo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingserver
function cleanup() {
    docker container stop "${CONTAINER_NAME}"
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

docker run -d --rm \
    -v "${PWD}/autobahn:/autobahn" \
    -p 9001:9001 \
    --init \
    --name "${CONTAINER_NAME}" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json'

sleep 3
cargo run --release --example autobahn-client --features=deflate
test_diff
