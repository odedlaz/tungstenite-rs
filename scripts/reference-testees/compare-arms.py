"""Compare two control arms case by case.

A reference peer that completes tells us nothing on its own: our own server role
completes about 86% of the time, so one quiet run is compatible with the
reference sharing the same intermittent failure. What discriminates is matched
per-case measurement -- the parameters each peer agreed, and how much work the
tester actually did under them. A reference that negotiated a narrower window or
no context takeover is doing structurally less peer-side work and would complete
for a reason that has nothing to do with us.
"""

import argparse
import glob
import json
import os
import re
import sys

EXTENSION_LINE = re.compile(r"^sec-websocket-extensions:(.*)$", re.IGNORECASE | re.MULTILINE)
TRAFFIC_FIELDS = [
    "incomingOctetsAppLevel",
    "incomingOctetsWireLevel",
    "incomingWebSocketFrames",
    "outgoingOctetsAppLevel",
    "outgoingOctetsWireLevel",
    "outgoingWebSocketFrames",
]


def load_arm(directory):
    cases = {}
    for path in glob.glob(os.path.join(directory, "*_case_*.json")):
        try:
            with open(path) as handle:
                report = json.load(handle)
        except (OSError, ValueError):
            continue
        case_id = report.get("id")
        if not case_id:
            continue
        match = EXTENSION_LINE.search(report.get("httpResponse") or "")
        cases[case_id] = {
            "extensions": " ".join((match.group(1) if match else "(none)").split()),
            "behavior": report.get("behavior"),
            "traffic": report.get("trafficStats") or {},
        }
    return cases


def normalize(extensions):
    """Parameter order is a free choice, so compare the set, not the string."""
    head, _, tail = extensions.partition(";")
    params = sorted(part.strip() for part in tail.split(";") if part.strip())
    return "; ".join([head.strip()] + params)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, help="arm whose peer is ours")
    parser.add_argument("--reference", required=True, help="arm whose peer is not ours")
    parser.add_argument("--baseline-name", default="baseline")
    parser.add_argument("--reference-name", default="reference")
    args = parser.parse_args()

    base, ref = load_arm(args.baseline), load_arm(args.reference)
    shared = sorted(set(base) & set(ref), key=lambda cid: [int(n) for n in cid.split(".")])
    compression = [cid for cid in shared if cid.split(".")[0] in ("12", "13")]

    mismatched = [cid for cid in compression
                  if normalize(base[cid]["extensions"]) != normalize(ref[cid]["extensions"])]

    print(f"### matched-parameter check: `{args.baseline_name}` vs `{args.reference_name}`")
    print()
    print(f"- cases in {args.baseline_name}: {len(base)}; in {args.reference_name}: {len(ref)}; shared: {len(shared)}")
    print(f"- shared groups 12/13: {len(compression)}")
    print(f"- **negotiated parameters differ on {len(mismatched)} of {len(compression)}**")
    print()
    if mismatched:
        print("| case | " + args.baseline_name + " | " + args.reference_name + " |")
        print("|---|---|---|")
        for cid in mismatched[:40]:
            print(f"| {cid} | `{base[cid]['extensions']}` | `{ref[cid]['extensions']}` |")
        if len(mismatched) > 40:
            print(f"| … | {len(mismatched) - 40} more | |")
        print()

    print("| tester work over shared 12/13 | " + args.baseline_name + " | " + args.reference_name + " |")
    print("|---|---|---|")
    for field in TRAFFIC_FIELDS:
        totals = [sum(arm[cid]["traffic"].get(field, 0) for cid in compression) for arm in (base, ref)]
        print(f"| {field} | {totals[0]:,} | {totals[1]:,} |")
    print()

    differing = [cid for cid in shared if base[cid]["behavior"] != ref[cid]["behavior"]]
    print(f"- behaviour differs on {len(differing)} shared cases"
          + (f": {', '.join(differing[:20])}" if differing else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
