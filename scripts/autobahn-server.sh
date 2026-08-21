#!/usr/bin/env bash
# Author michael <themichaeleden@gmail.com>
#
# SCRATCH BRANCH ONLY -- instrumented to diagnose the intermittent CI failure in
# the server suite. Not for upstream. Every change below exists because the
# stock script destroys the evidence the failure leaves:
#
#   set -e            exit 137 from `docker run` jumped straight to the EXIT trap,
#                     so nothing could inspect the container afterwards
#   --rm              the container was gone before .State.OOMKilled could be read.
#                     Measured since: a host-level (CONSTRAINT_NONE) kill sets that
#                     flag too, so it does not by itself mean a cgroup limit was hit
#                     -- the kernel record below is what distinguishes them
#   cargo run &       $! is the cargo wrapper, so `wait` proved nothing about the
#                     Rust server and killing it could orphan the real listener
#   block buffering   wstest's stdout flushed every ~103 cases, so the last case
#                     ID in the log named a buffer boundary and not a case
set -uo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.." || exit 1

CONTAINER=autobahn-fuzzingclient
MEMLOG=$(mktemp)
# A hang costs this instead of the job's six-hour default. `timeout` kills the
# docker client and leaves the container itself running, so the postmortem can
# tell a hang (still Running) from a kill (OOMKilled or a nonzero ExitCode).
CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-15m}
# The kernel killed wstest at 14.9 GiB of anon-rss with constraint=CONSTRAINT_NONE,
# i.e. the host ran out; the runner puts no cgroup limit on containers. A limit
# here turns that into cgroup pressure, which can reclaim and swap instead of
# killing. Whether the client then completes or dies at the cap is the question:
# completing makes the fix one flag upstream, dying says it needs more than this.
CLIENT_MEMORY=${CLIENT_MEMORY:-6g}

function cleanup() {
    [ -n "${WSSERVER_PID:-}" ] && kill -9 "${WSSERVER_PID}" 2>/dev/null
    [ -n "${SAMPLER_PID:-}" ] && kill "${SAMPLER_PID}" 2>/dev/null
    docker rm -f "${CONTAINER}" >/dev/null 2>&1
    return 0
}
trap cleanup TERM EXIT

function test_diff() {
    if ! diff -q \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' 'autobahn/expected-results.json') \
        <(jq -S 'del(."Tungstenite" | .. | .duration?)' 'autobahn/server/index.json')
    then
        echo 'Difference in results, either this is a regression or' \
             'one should update autobahn/expected-results.json with the new results.'
        exit 64
    fi
}

# Build first so the pid we track is the server itself and not cargo.
cargo build --release --example autobahn-server --features=deflate
./target/release/examples/autobahn-server & WSSERVER_PID=$!
sleep 3
kill -0 "${WSSERVER_PID}" || { echo 'server did not start'; exit 70; }

{ set +x
  while true; do
      printf '%s client=%s server_rss_kb=%s\n' "$(date -u +%H:%M:%S)" \
          "$(docker stats --no-stream --format '{{.MemUsage}}' "${CONTAINER}" 2>/dev/null | cut -d/ -f1)" \
          "$(ps -o rss= -p "${WSSERVER_PID}" 2>/dev/null | tr -d ' ')" >> "${MEMLOG}"
      sleep 5
  done
} &
SAMPLER_PID=$!

# PYTHONUNBUFFERED so a case ID means a case. The trailing echo reports the
# cgroup's own high-water mark, which sampling can miss; an OOM kill loses that
# line, and .State.OOMKilled below covers exactly that case.
# shellcheck disable=SC2016  # the inner quotes are the container shell's, not ours
timeout "${CLIENT_TIMEOUT}" docker run --name "${CONTAINER}" \
    --memory="${CLIENT_MEMORY}" \
    -e PYTHONUNBUFFERED=1 \
    -v "${PWD}/autobahn:/autobahn" \
    --network host \
    --entrypoint sh \
    crossbario/autobahn-testsuite \
    -c 'wstest -m fuzzingclient -s autobahn/fuzzingclient.json; rc=$?;
        echo "CGROUP_MEMORY_PEAK_BYTES=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo unavailable)";
        exit $rc'
CLIENT_STATUS=$?
kill "${SAMPLER_PID}" 2>/dev/null

# Postmortem before anything is removed. Reached on failure too, which is the
# whole point of dropping errexit.
SERVER_ALIVE=no; kill -0 "${WSSERVER_PID}" 2>/dev/null && SERVER_ALIVE=yes
{ set +x
  echo "=== postmortem ==="
  echo "client status      : ${CLIENT_STATUS}   (124 = our timeout fired)"
  echo "server still alive : ${SERVER_ALIVE}"
  docker inspect "${CONTAINER}" --format \
      'container Running: {{.State.Running}}  OOMKilled: {{.State.OOMKilled}}  ExitCode: {{.State.ExitCode}}  Error: {{.State.Error}}'
  echo "--- container memory samples ---"
  cat "${MEMLOG}"
  echo "--- kernel OOM record, if the runner exposes one ---"
  sudo dmesg 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -20 || echo 'dmesg unavailable'
  echo "=== end postmortem ==="
}

[ "${CLIENT_STATUS}" -ne 0 ] && exit "${CLIENT_STATUS}"
test_diff
