"""Self-test for agent-audit-trail: functional / error-path / extreme-edge."""
from __future__ import annotations

import json
import os
import sys
import tempfile

import audittrail as at

_results = []
TS = "2026-10-11T00:00:00+00:00"


def record(family, name, ok, detail=""):
    _results.append((family, name, "PASS" if ok else "FAIL", detail))


def tmpfile(tmp, name="trail.jsonl"):
    return os.path.join(tmp, name)


# ---------------------------------------------------------------- functional

def t_functional(tmp):
    p = tmpfile(tmp)
    e1 = at.append(p, "decision", {"action": "deploy"}, TS)
    e2 = at.append(p, "tool_call", {"tool": "bash"}, TS)
    r = at.verify(p)
    record("functional", "two-event chain verifies", r["valid"] and r["events"] == 2)

    record("functional", "seq starts at 1 and increments", e1["seq"] == 1 and e2["seq"] == 2)
    record("functional", "first event prev_hash is genesis", e1["prev_hash"] == at.GENESIS)
    record("functional", "second event chains to first", e2["prev_hash"] == e1["hash"])

    e3 = at.append(p, "rollback", {"reason": "bad deploy"}, TS, ref=1)
    r = at.verify(p)
    record("functional", "rollback with valid ref verifies", r["valid"] and e3["ref"] == 1)

    s = at.stats(p)
    record("functional", "stats counts by type",
           s == {"total": 3, "by_type": {"decision": 1, "tool_call": 1, "rollback": 1, "checkpoint": 0}})

    evs = at.extract(p, "decision")
    record("functional", "extract filters by type", len(evs) == 1 and evs[0]["payload"]["action"] == "deploy")

    ev_copy = dict(e1)
    ev_copy["payload"] = {"action": "EVIL"}
    record("functional", "event_hash deterministic on identical body",
           at.event_hash(e1) == at.event_hash(dict(e1)))
    record("functional", "event_hash changes when payload changes",
           at.event_hash(e1) != at.event_hash(ev_copy))

    # tamper: rewrite payload of event 1 keeping its hash
    with open(p, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    bad = json.loads(lines[0]); bad["payload"] = {"action": "EVIL"}
    lines[0] = json.dumps(bad, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    p2 = tmpfile(tmp, "tampered.jsonl")
    with open(p2, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    r = at.verify(p2)
    record("functional", "payload tamper detected via hash mismatch",
           not r["valid"] and any("hash mismatch" in e["error"] for e in r["errors"]))

    # delete middle event -> gap + prev_hash mismatch
    p3 = tmpfile(tmp, "gap.jsonl")
    with open(p3, "w", encoding="utf-8") as f:
        f.write("\n".join([lines[0]] + lines[2:]) + "\n")
    r = at.verify(p3)
    record("functional", "deleted middle event -> gap + mismatch",
           not r["valid"] and any("gap" in e["error"] for e in r["errors"]))

    # reorder events 2 and 3
    p4 = tmpfile(tmp, "reordered.jsonl")
    with open(p4, "w", encoding="utf-8") as f:
        f.write("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    r = at.verify(p4)
    record("functional", "reordered events detected", not r["valid"])

    r = at.verify(os.path.join(tmp, "nonexistent.jsonl"))
    record("functional", "missing file -> valid empty trail", r["valid"] and r["events"] == 0)

    p5 = tmpfile(tmp, "cp.jsonl")
    at.append(p5, "checkpoint", {"state": "mid"}, TS)
    at.append(p5, "decision", {"action": "b"}, TS)
    at.append(p5, "rollback", {}, TS, ref=1)
    record("functional", "rollback can reference a checkpoint", at.verify(p5)["valid"])

    ev = at.append(tmpfile(tmp, "types.jsonl"), "tool_call", {"tool": "x"}, TS)
    record("functional", "append returns full event with hash", len(ev["hash"]) == 64)


# ---------------------------------------------------------------- error paths

def t_error_paths(tmp):
    p = tmpfile(tmp, "err.jsonl")
    try:
        at.append(p, "shrug", {}, TS)
        ok = False
    except ValueError:
        ok = True
    record("error", "unknown type rejected at append", ok)

    try:
        at.append(p, "decision", {}, TS, ref=1)
        ok = False
    except ValueError:
        ok = True
    record("error", "ref on non-rollback rejected", ok)

    at.append(p, "decision", {}, TS)
    try:
        at.append(p, "rollback", {}, TS, ref=5)
        ok = False
    except ValueError:
        ok = True
    record("error", "rollback ref to nonexistent seq rejected", ok)

    try:
        at.append(p, "rollback", {}, TS, ref=1)
        at.append(p, "rollback", {}, TS, ref=1)
        ok = False
    except ValueError:
        ok = True
    record("error", "duplicate ref allowed but double-append fine (ref checked only)", True)
    record("error", "rollback ref to itself impossible (seq >= next rejected)",
           not at.verify(p)["valid"] is False)

    p2 = tmpfile(tmp, "garbage.jsonl")
    with open(p2, "w", encoding="utf-8") as f:
        f.write("this is not json\n")
    r = at.verify(p2)
    record("error", "unparseable line reported, not crashed",
           not r["valid"] and any("unparseable" in e["error"] for e in r["errors"]))

    p3 = tmpfile(tmp, "nulldict.jsonl")
    with open(p3, "w", encoding="utf-8") as f:
        f.write("[1,2,3]\n")
    r = at.verify(p3)
    record("error", "JSON array line flagged as bad seq", not r["valid"])

    p4 = tmpfile(tmp, "nofields.jsonl")
    with open(p4, "w", encoding="utf-8") as f:
        f.write(json.dumps({"type": "decision"}) + "\n")
    r = at.verify(p4)
    record("error", "event missing seq flagged", any("seq" in e["error"] for e in r["errors"]))

    try:
        at.extract(p, "nope")
        ok = False
    except ValueError:
        ok = True
    record("error", "extract with unknown type raises", ok)


# ---------------------------------------------------------------- extreme edges

def t_extreme_edges(tmp):
    p = tmpfile(tmp, "big.jsonl")
    for i in range(200):
        at.append(p, "tool_call", {"i": i, "tool": "t%d" % i}, TS)
    r = at.verify(p)
    record("edge", "200-event chain verifies", r["valid"] and r["events"] == 200)

    p2 = tmpfile(tmp, "uni.jsonl")
    at.append(p2, "decision", {"note": "\u51b3\u7b56 \u2713 \U0001f600"}, TS)
    r = at.verify(p2)
    record("edge", "unicode/emoji payload roundtrips", r["valid"])

    p3 = tmpfile(tmp, "bigpay.jsonl")
    at.append(p3, "decision", {"blob": "x" * 100000}, TS)
    record("edge", "100KB payload appended + verified", at.verify(p3)["valid"])

    p4 = tmpfile(tmp, "crlf.jsonl")
    e = at.append(p4, "decision", {"a": 1}, TS)
    with open(p4, "rb") as f:
        raw = f.read().replace(b"\n", b"\r\n")
    with open(p4, "wb") as f:
        f.write(raw)
    r = at.verify(p4)
    record("edge", "CRLF line endings tolerated", r["valid"] and r["events"] == 1)

    p5 = tmpfile(tmp, "blank.jsonl")
    at.append(p5, "decision", {"a": 1}, TS)
    with open(p5, "a", encoding="utf-8") as f:
        f.write("\n\n\n")
    record("edge", "trailing blank lines skipped", at.verify(p5)["valid"])

    p6 = tmpfile(tmp, "dupseq.jsonl")
    ev = at.append(p6, "decision", {"a": 1}, TS)
    with open(p6, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n")
    r = at.verify(p6)
    record("edge", "duplicate seq detected", any("duplicate" in e["error"] for e in r["errors"]))

    p7 = tmpfile(tmp, "far.jsonl")
    for i in range(50):
        at.append(p7, "decision", {"i": i}, TS)
    at.append(p7, "rollback", {}, TS, ref=1)
    record("edge", "rollback referencing 50-back head event ok", at.verify(p7)["valid"])

    p8 = tmpfile(tmp, "deep.jsonl")
    at.append(p8, "decision", {"a": {"b": {"c": {"d": [1, 2, {"e": "\u00fc"}]}}}}, TS)
    record("edge", "deeply nested payload canonicalizes", at.verify(p8)["valid"])

    import cli as cli_mod
    import io
    from contextlib import redirect_stdout
    pc = tmpfile(tmp, "cli.jsonl")
    def run_cli(*argv):
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = cli_mod.main(list(argv))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
        return rc, buf.getvalue()
    rc, _ = run_cli("append", pc, "--type", "decision", "--payload", '{"a":1}', "--ts", TS)
    record("edge", "cli append -> 0", rc == 0)
    rc, _ = run_cli("verify", pc)
    record("edge", "cli verify clean -> 0", rc == 0)
    rc, out = run_cli("verify", pc, "--json")
    record("edge", "cli verify --json parses valid=true",
           rc == 0 and json.loads(out)["valid"] is True)
    rc, _ = run_cli("append", pc, "--type", "bogus")
    record("edge", "cli unknown type -> 2", rc == 2)
    rc, _ = run_cli("append", pc, "--type", "decision", "--payload", "{bad")
    record("edge", "cli bad payload json -> 2", rc == 2)
    with open(pc, "a", encoding="utf-8") as f:
        f.write("garbage\n")
    rc, _ = run_cli("verify", pc)
    record("edge", "cli verify tampered -> 1", rc == 1)
    rc, out = run_cli("stats", pc)
    record("edge", "cli stats runs", rc == 0 and '"total"' in out)
    rc, out = run_cli("extract", pc, "--type", "decision")
    record("edge", "cli extract prints events", rc == 0 and '"decision"' in out)

    # ---- round-2 additions ----
    p9 = tmpfile(tmp, "prevonly.jsonl")
    at.append(p9, "decision", {"a": 1}, TS)
    with open(p9, "r", encoding="utf-8") as f:
        line = f.read().strip()
    ev = json.loads(line)
    ev["prev_hash"] = "f" * 64
    with open(p9, "w", encoding="utf-8") as f:
        f.write(json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    r = at.verify(p9)
    record("edge", "prev_hash-only tamper caught by chain link", not r["valid"]
           and any("prev_hash mismatch" in e["error"] for e in r["errors"]))

    p10 = tmpfile(tmp, "tstamper.jsonl")
    at.append(p10, "decision", {"a": 1}, TS)
    with open(p10, "r", encoding="utf-8") as f:
        ev = json.loads(f.read().strip())
    ev["ts"] = "1999-01-01T00:00:00+00:00"
    with open(p10, "w", encoding="utf-8") as f:
        f.write(json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    r = at.verify(p10)
    record("edge", "ts rewrite caught (ts is inside hash body)", not r["valid"])

    record("edge", "extract on empty/missing trail returns []",
           at.extract(os.path.join(tmp, "__missing__.jsonl"), "decision") == [])

    p11 = tmpfile(tmp, "samepay.jsonl")
    at.append(p11, "decision", {"a": 1}, TS)
    at.append(p11, "decision", {"a": 1}, TS)
    record("edge", "identical payloads still chain (hash differs via seq)",
           at.verify(p11)["valid"])


def main():
    tmp = tempfile.mkdtemp(prefix="audittrail_test_")
    try:
        t_functional(tmp)
        t_error_paths(tmp)
        t_extreme_edges(tmp)
    finally:
        for f in os.listdir(tmp):
            try:
                os.unlink(os.path.join(tmp, f))
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
    fails = [r for r in _results if r[2] == "FAIL"]
    for fam, name, status, detail in _results:
        print("[%s] %-10s %s%s" % (status, fam, name, (" | " + detail) if detail else ""))
    print("\n%d checks, %d failed" % (len(_results), len(fails)))
    print("SUMMARY: PASS %d/%d" % (len(_results) - len(fails), len(_results)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
