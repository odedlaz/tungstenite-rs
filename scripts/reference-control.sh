#!/usr/bin/env bash
# SCRATCH BRANCH ONLY. Not for upstream.
#
# Swaps the peer under `wstest -m fuzzingclient` and measures the tester's own
# memory. The question this answers: is the exit-137 abort a property of the
# Autobahn tester running groups 12/13 against any conforming peer, or of
# something our server sends? Every arm shares one image digest, one memory cap,
# one spec and one sampler, so the peer is the only variable.
#
# The arm never fails on an OOM kill -- that is a result, not an error. It fails
# only when the arm cannot answer the question: exit 66 when the peer declines
# the compression cases, because then the tester never did the work being
# measured and a quiet arm means nothing.
set -uo pipefail

SOURCE_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
cd "${SOURCE_DIR}/.." || exit 1

TESTEE=${TESTEE:?set TESTEE to tungstenite|tungstenite-plain|node-ws|python-websockets|autobahn-testee}
CLIENT_MEMORY=${CLIENT_MEMORY:-6g}
RUN_TIMEOUT=${RUN_TIMEOUT:-1500}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-1}
# Digest-pinned, not `:latest`: an image that moves mid-experiment turns the
# peer comparison into a peer-and-tester comparison.
IMAGE=${IMAGE:-crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074}

CONTAINER=autobahn-fuzzingclient-control
TESTEE_CONTAINER=autobahn-reference-testee
OUTDIR=autobahn/control-out
MEMLOG=${OUTDIR}/memory-samples.tsv
CASELOG=${OUTDIR}/wstest.log
TESTEE_LOG=${OUTDIR}/testee.log

case "${TESTEE}" in
    tungstenite)       AGENT=Tungstenite ;;
    tungstenite-plain) AGENT=TungstenitePlain ;;
    node-ws)           AGENT=NodeWs ;;
    python-websockets) AGENT=PythonWebsockets ;;
    autobahn-testee)   AGENT=AutobahnTestee ;;
    *) echo "unknown TESTEE: ${TESTEE}"; exit 2 ;;
esac

function cleanup() {
    [ -n "${SAMPLER_PID:-}" ] && kill "${SAMPLER_PID}" 2>/dev/null
    [ -n "${LOGGER_PID:-}" ] && kill "${LOGGER_PID}" 2>/dev/null
    [ -n "${TESTEE_PID:-}" ] && kill -9 "${TESTEE_PID}" 2>/dev/null
    docker rm -f "${TESTEE_CONTAINER}" >/dev/null 2>&1
    docker rm -f "${CONTAINER}" >/dev/null 2>&1
    return 0
}
trap cleanup TERM EXIT

set -x
# Truncate, do not append. A second arm run in the same tree inherited the first
# arm's case log, and since the summary places a memory crossing by the last case
# logged at or before it, that silently attributes one peer's cases to another.
rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}" autobahn/server
rm -f autobahn/server/*.json

# ---------------------------------------------------------------- start peer
case "${TESTEE}" in
    tungstenite)
        cargo build --release --example autobahn-server --features=deflate || exit 70
        ./target/release/examples/autobahn-server >"${TESTEE_LOG}" 2>&1 & TESTEE_PID=$!
        ;;
    tungstenite-plain)
        cargo build --release --example autobahn-server-plain || exit 70
        ./target/release/examples/autobahn-server-plain >"${TESTEE_LOG}" 2>&1 & TESTEE_PID=$!
        ;;
    node-ws)
        npm install --silent --no-fund --no-audit --prefix /tmp/ws-testee ws@8.18.0 || exit 70
        NODE_PATH=/tmp/ws-testee/node_modules \
            node scripts/reference-testees/node-ws.js >"${TESTEE_LOG}" 2>&1 & TESTEE_PID=$!
        ;;
    python-websockets)
        python3 -m venv /tmp/ws-venv || exit 70
        /tmp/ws-venv/bin/pip install --quiet websockets==14.2 || exit 70
        /tmp/ws-venv/bin/python scripts/reference-testees/python-websockets.py \
            >"${TESTEE_LOG}" 2>&1 & TESTEE_PID=$!
        ;;
    autobahn-testee)
        docker run -d --name "${TESTEE_CONTAINER}" --network host \
            --entrypoint sh "${IMAGE}" \
            -c 'wstest -m testeeserver -w ws://127.0.0.1:9002' || exit 70
        ;;
esac

# `nc`/`curl` are not uniformly present and a TCP connect is what we mean.
{ set +x
  ready=no
  for _ in $(seq 1 90); do
      if (exec 3<>/dev/tcp/127.0.0.1/9002) 2>/dev/null; then exec 3>&-; ready=yes; break; fi
      sleep 1
  done
}
set -x
if [ "${ready}" != yes ]; then
    echo "peer ${TESTEE} never listened on 9002"
    cat "${TESTEE_LOG}" 2>/dev/null
    docker logs "${TESTEE_CONTAINER}" 2>&1 | tail -40
    exit 70
fi

# The negotiated header is in every per-case report, but an OOM-killed arm writes
# none -- and that arm's negotiation is the one in question. Probe it up front so
# every arm has the fingerprint regardless of how it ends.
python3 scripts/reference-testees/handshake-probe.py > "${OUTDIR}/negotiation.txt" 2>&1

# ------------------------------------------------------- start the fuzzing client
# Only the agent label differs from the shipping spec, so the index and per-case
# filenames say which peer produced them.
jq --arg agent "${AGENT}" '.servers[0].agent = $agent' \
    autobahn/fuzzingclient.json > autobahn/fuzzingclient-control.json || exit 2

# Detached, so the sampler can find the container's cgroup while it runs and the
# exit code still comes back from `docker wait`.
docker run -d --name "${CONTAINER}" \
    --memory="${CLIENT_MEMORY}" \
    -e PYTHONUNBUFFERED=1 \
    -v "${PWD}/autobahn:/autobahn" \
    --network host \
    --entrypoint sh "${IMAGE}" \
    -c 'wstest -m fuzzingclient -s autobahn/fuzzingclient-control.json' || exit 70

# Docker defaults to a private cgroup namespace on cgroup v2, so the container's
# own /proc says `0::/` and cannot locate itself. Resolve from the host by id,
# and require memory.current to exist before trusting a candidate.
CID=$(docker inspect -f '{{.Id}}' "${CONTAINER}")
CPID=$(docker inspect -f '{{.State.Pid}}' "${CONTAINER}")
CGDIR=
for candidate in \
    "/sys/fs/cgroup/system.slice/docker-${CID}.scope" \
    "/sys/fs/cgroup/docker/${CID}" \
    "/sys/fs/cgroup$(awk -F: '$1=="0"{print $3}' "/proc/${CPID}/cgroup" 2>/dev/null)"
do
    [ -r "${candidate}/memory.current" ] && { CGDIR=${candidate}; break; }
done
if [ -z "${CGDIR}" ]; then
    CGDIR=$(find /sys/fs/cgroup -maxdepth 5 -type d -name "*${CID}*" 2>/dev/null | head -1)
fi
echo "cgroup for ${CONTAINER}: ${CGDIR:-NOT FOUND}"

# An OOM kill takes the container's own shell with it, so the peak has to be read
# from outside. `memory.peak` is monotonic, so the last sample that lands before
# the kill carries the high-water mark.
{ set +x
  printf 'epoch\tcurrent_bytes\tpeak_bytes\tpeer_rss_kb\n' > "${MEMLOG}"
  while true; do
      if [ -n "${CGDIR}" ]; then
          cur=$(cat "${CGDIR}/memory.current" 2>/dev/null || echo -1)
          pk=$(cat "${CGDIR}/memory.peak" 2>/dev/null || echo -1)
      else
          # No host cgroupfs (a Docker Desktop VM). Coarser and slower than the
          # cgroup files, and it loses the true high-water mark between ticks,
          # but it keeps the harness reproducible off a Linux runner.
          cur=$(docker stats --no-stream --format '{{.MemUsage}}' "${CONTAINER}" 2>/dev/null \
              | awk -F/ '{gsub(/[[:space:]]/,"",$1); u=$1; sub(/[KMGi]*B$/,"",u)
                          m=1; if ($1 ~ /KiB/) m=1024; else if ($1 ~ /MiB/) m=1048576
                          else if ($1 ~ /GiB/) m=1073741824
                          printf "%d", u*m}')
          pk=-1
      fi
      if [ -n "${TESTEE_PID:-}" ]; then
          rss=$(ps -o rss= -p "${TESTEE_PID}" 2>/dev/null | tr -d ' ')
      else
          rss=$(docker stats --no-stream --format '{{.MemUsage}}' "${TESTEE_CONTAINER}" 2>/dev/null | cut -d/ -f1)
      fi
      # EPOCHREALTIME rather than `date +%s.%3N`: no subprocess per tick, and %N
      # is GNU-only, which silently stamped every local sample unparseable.
      printf '%s\t%s\t%s\t%s\n' "${EPOCHREALTIME:-$(date +%s)}" "${cur:--1}" "${pk}" "${rss:--1}" >> "${MEMLOG}"
      sleep "${SAMPLE_INTERVAL}"
  done
} &
SAMPLER_PID=$!

# Host-stamped so a case ID can be placed on the memory curve. wstest block-buffers
# without PYTHONUNBUFFERED, which is why the stock log's last case named a buffer
# boundary rather than the case that was running.
docker logs -f "${CONTAINER}" 2>&1 \
    | python3 -u -c 'import sys,time
for line in sys.stdin:
    sys.stdout.write("%.3f %s" % (time.time(), line))' >> "${CASELOG}" &
LOGGER_PID=$!

# `timeout` is GNU-only. Without it the CI job's own ceiling is the backstop; the
# point of keeping this runnable off a Linux runner is that local reproduction is
# the fast loop, and a missing binary should not silently report a timeout.
TIMEOUT_BIN=$(command -v timeout || command -v gtimeout || true)
if CLIENT_STATUS=$(${TIMEOUT_BIN:+"${TIMEOUT_BIN}" "${RUN_TIMEOUT}"} docker wait "${CONTAINER}"); then
    :
else
    CLIENT_STATUS=timeout
    docker stop -t 5 "${CONTAINER}" >/dev/null 2>&1
fi
kill "${SAMPLER_PID}" 2>/dev/null; SAMPLER_PID=
sleep 1
kill "${LOGGER_PID}" 2>/dev/null; LOGGER_PID=

PEER_ALIVE=unknown
[ -n "${TESTEE_PID:-}" ] && { PEER_ALIVE=no; kill -0 "${TESTEE_PID}" 2>/dev/null && PEER_ALIVE=yes; }

docker inspect "${CONTAINER}" --format \
    'OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} Error={{.State.Error}}' \
    > "${OUTDIR}/container-state.txt" 2>&1
cp autobahn/server/index.json "${OUTDIR}/index.json" 2>/dev/null
{ set +x
  sudo -n dmesg 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -20 \
      > "${OUTDIR}/dmesg-oom.txt" || echo 'dmesg unavailable' > "${OUTDIR}/dmesg-oom.txt"
  tail -50 "${TESTEE_LOG}" > "${OUTDIR}/testee-tail.log" 2>/dev/null
}
set -x

python3 scripts/reference-testees/summarize.py \
    --testee "${TESTEE}" --agent "${AGENT}" \
    --client-status "${CLIENT_STATUS}" --peer-alive "${PEER_ALIVE}" \
    --memlog "${MEMLOG}" --caselog "${CASELOG}" \
    --index autobahn/server/index.json \
    --state "${OUTDIR}/container-state.txt" \
    --negotiation "${OUTDIR}/negotiation.txt" \
    --cap "${CLIENT_MEMORY}" --image "${IMAGE}" \
    | tee "${OUTDIR}/summary.md"
exit "${PIPESTATUS[0]}"
