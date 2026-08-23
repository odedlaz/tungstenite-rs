"""Turn one control arm's raw logs into the numbers the experiment asks for.

Two questions per arm: how much memory did `wstest` demand, and which case was
running when it took off. The second needs the tester's case log and the memory
samples on one clock, which is why both are host-stamped.
"""

import argparse
import json
import re
import sys

MIB = 1024 * 1024
GIB = 1024 * MIB
THRESHOLDS = [256 * MIB, 512 * MIB, GIB, 2 * GIB, 4 * GIB]
CASE_LINE = re.compile(r"case ID ([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)
# The declined path costs 106 ms across all 216 cases, so seconds of group-12/13
# wall time is unambiguous evidence the compression cases really executed.
DECLINED_CEILING_SECONDS = 5.0


def read_samples(path):
    rows = []
    try:
        with open(path) as handle:
            next(handle, None)
            for line in handle:
                parts = line.split("\t")
                if len(parts) < 3:
                    continue
                try:
                    rows.append((float(parts[0]), int(parts[1]), int(parts[2])))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


def read_cases(path):
    cases = []
    try:
        with open(path) as handle:
            for line in handle:
                match = CASE_LINE.search(line)
                if not match:
                    continue
                try:
                    stamp = float(line.split(" ", 1)[0])
                except ValueError:
                    continue
                case = match.group(1)
                if not cases or cases[-1][1] != case:
                    cases.append((stamp, case))
    except OSError:
        pass
    return cases


def case_at(cases, stamp):
    running = [c for t, c in cases if t <= stamp]
    return running[-1] if running else "unknown"


def group_seconds(cases, groups):
    """Wall time the tester spent inside the named case groups."""
    total = 0.0
    for index, (stamp, case) in enumerate(cases):
        if case.split(".")[0] not in groups:
            continue
        end = cases[index + 1][0] if index + 1 < len(cases) else stamp
        total += end - stamp
    return total


def human(value):
    if value < 0:
        return "n/a"
    if value >= GIB:
        return f"{value / GIB:.2f} GiB"
    return f"{value / MIB:.0f} MiB"


def read_text(path):
    try:
        return open(path).read()
    except OSError:
        return ""


def read_index(path, agent):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data.get(agent) or (next(iter(data.values())) if len(data) == 1 else None)


def main():
    parser = argparse.ArgumentParser()
    for flag in ("testee", "agent", "client-status", "peer-alive", "memlog",
                 "caselog", "index", "state", "negotiation", "cap", "image"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()

    samples = read_samples(args.memlog)
    cases = read_cases(args.caselog)
    sampled_peak = max((row[1] for row in samples), default=-1)
    cgroup_peak = max((row[2] for row in samples), default=-1)
    peak = max(cgroup_peak, sampled_peak)

    state = read_text(args.state).strip() or "unavailable"

    index = read_index(args.index, args.agent)
    compression = [(cid, entry.get("behavior")) for cid, entry in (index or {}).items()
                   if cid.split(".")[0] in ("12", "13")]
    executed = [cid for cid, behavior in compression if behavior != "UNIMPLEMENTED"]
    tally = {}
    for entry in (index or {}).values():
        tally[entry.get("behavior")] = tally.get(entry.get("behavior"), 0) + 1

    compression_seconds = group_seconds(cases, ("12", "13"))
    if index is not None:
        did_compress = len(executed) > 0
        basis = f"{len(executed)}/{len(compression)} group-12/13 cases with behavior != UNIMPLEMENTED"
    else:
        did_compress = compression_seconds > DECLINED_CEILING_SECONDS
        basis = (f"no index (run did not finish); {compression_seconds:.1f}s of tester wall time "
                 f"inside groups 12/13, against {DECLINED_CEILING_SECONDS}s for the declined path")

    out = [
        f"### control arm: `{args.testee}` (agent `{args.agent}`)",
        "",
        "| field | value |",
        "|---|---|",
        f"| image | `{args.image}` |",
        f"| memory cap | {args.cap} |",
        f"| wstest exit | `{args.client_status}` |",
        f"| container state | `{state}` |",
        f"| peer still alive | {args.peer_alive} |",
        f"| **wstest peak memory** | **{human(peak)}** (cgroup {human(cgroup_peak)}, sampled {human(sampled_peak)}) |",
        f"| cases started (from log) | {len(cases)} |",
        f"| index.json | {'present' if index is not None else 'ABSENT'} |",
        f"| index case count | {len(index) if index is not None else 'n/a'} |",
        f"| index behaviors | {tally or 'n/a'} |",
        f"| groups 12/13 executed | {'YES' if did_compress else 'NO'} — {basis} |",
        f"| tester wall time in 12/13 | {compression_seconds:.1f}s |",
        "",
        "| memory crossed | at case |",
        "|---|---|",
    ]
    for threshold in THRESHOLDS:
        crossing = next((row[0] for row in samples if row[1] >= threshold), None)
        out.append(f"| {human(threshold)} | "
                   + (f"`{case_at(cases, crossing)}`" if crossing else "never reached")
                   + " |")
    if samples:
        out.append(f"| peak, last sample | `{case_at(cases, samples[-1][0])}` |")
    out += ["", "<details><summary>negotiation fingerprint</summary>", "",
            "```", read_text(args.negotiation).rstrip(), "```", "</details>", ""]
    print("\n".join(out))

    if args.testee == "tungstenite-plain":
        return 0
    if not did_compress:
        print(f"PRECONDITION FAILED: peer `{args.testee}` did not exercise the compression "
              "cases, so this arm measures nothing about the tester's behaviour under them.")
        return 66
    return 0


if __name__ == "__main__":
    sys.exit(main())
