"""CLI for agent-audit-trail."""
import argparse
import json
import sys
from datetime import datetime, timezone

import audittrail


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agent-audit-trail",
                                 description="Append-only hash-chained JSONL audit trail for AI agent decisions, tool calls and rollbacks.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_a = sub.add_parser("append", help="append an event")
    p_a.add_argument("trail")
    p_a.add_argument("--type", required=True, choices=audittrail.TYPES)
    p_a.add_argument("--payload", default="{}", help="JSON object payload")
    p_a.add_argument("--ref", type=int, default=None, help="seq to roll back (rollback events only)")
    p_a.add_argument("--ts", default=None, help="ISO-8601 timestamp (default: now UTC)")

    p_v = sub.add_parser("verify", help="verify chain integrity")
    p_v.add_argument("trail")
    p_v.add_argument("--json", action="store_true")

    p_s = sub.add_parser("stats", help="per-type counts")
    p_s.add_argument("trail")

    p_e = sub.add_parser("extract", help="print events of one type")
    p_e.add_argument("trail")
    p_e.add_argument("--type", required=True, choices=audittrail.TYPES)

    args = ap.parse_args(argv)

    if args.cmd == "append":
        try:
            payload = json.loads(args.payload)
        except ValueError as e:
            print("error: payload is not valid JSON: %s" % e, file=sys.stderr)
            return 2
        if not isinstance(payload, dict):
            print("error: payload must be a JSON object", file=sys.stderr)
            return 2
        ts = args.ts or datetime.now(timezone.utc).isoformat()
        try:
            ev = audittrail.append(args.trail, args.type, payload, ts, args.ref)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        print("appended seq=%d type=%s hash=%s..." % (ev["seq"], ev["type"], ev["hash"][:12]))
        return 0

    if args.cmd == "verify":
        rep = audittrail.verify(args.trail)
        if args.json:
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        else:
            print("valid: %s | events: %d | errors: %d" % (rep["valid"], rep["events"], len(rep["errors"])))
            for e in rep["errors"]:
                print("  seq %s: %s" % (e["seq"], e["error"]))
        return 0 if rep["valid"] else 1

    if args.cmd == "stats":
        s = audittrail.stats(args.trail)
        print(json.dumps(s, indent=2))
        return 0

    if args.cmd == "extract":
        try:
            evs = audittrail.extract(args.trail, args.type)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        for ev in evs:
            print(json.dumps(ev, ensure_ascii=False))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
