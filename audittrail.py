"""agent-audit-trail: append-only, hash-chained JSONL audit trail for AI agents.

Event schema (one JSON object per line):
  seq        int, 1-based, gapless
  ts         ISO-8601 string (caller supplied)
  type       decision | tool_call | rollback | checkpoint
  payload    arbitrary JSON object
  ref        (rollback only) seq of the event being rolled back
  prev_hash  hex sha256 of the previous event ("0"*64 for the first)
  hash       hex sha256(prev_hash + canonical_json(event_without_hash))

verify recomputes the chain and reports tamper / gap / reorder / bad-type /
broken-rollback findings without crashing on malformed lines.
"""
from __future__ import annotations

import hashlib
import json
import os

TYPES = ("decision", "tool_call", "rollback", "checkpoint")
GENESIS = "0" * 64


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256((event.get("prev_hash", GENESIS) + canonical(body)).encode("utf-8")).hexdigest()


def make_event(seq: int, ts: str, etype: str, payload: dict, prev_hash: str, ref=None) -> dict:
    ev = {"seq": seq, "ts": ts, "type": etype, "payload": payload,
          "prev_hash": prev_hash}
    if ref is not None:
        ev["ref"] = ref
    ev["hash"] = event_hash(ev)
    return ev


def append(path: str, etype: str, payload: dict, ts: str, ref=None) -> dict:
    """Append one event; validates type and rollback ref. Raises ValueError on bad input."""
    if etype not in TYPES:
        raise ValueError("unknown event type: %s (valid: %s)" % (etype, ",".join(TYPES)))
    seq, prev_hash, known = next_seq_and_head(path)
    if ref is not None:
        if etype != "rollback":
            raise ValueError("ref is only valid on rollback events")
        if not isinstance(ref, int) or ref < 1 or ref >= seq:
            raise ValueError("rollback ref must point to an earlier event seq, got %r" % (ref,))
    ev = make_event(seq, ts, etype, payload, prev_hash, ref)
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical(ev) + "\n")
    return ev


def next_seq_and_head(path: str) -> tuple:
    """Scan the file: returns (next_seq, last_hash, known_seqs set)."""
    seq, last_hash, known = 1, GENESIS, set()
    for ev in iter_events(path):
        if isinstance(ev, dict) and isinstance(ev.get("seq"), int):
            known.add(ev["seq"])
            if ev["seq"] >= seq:
                seq = ev["seq"] + 1
        if isinstance(ev, dict) and isinstance(ev.get("hash"), str):
            last_hash = ev["hash"]
    return seq, last_hash, known


def iter_events(path: str):
    """Yield parsed events; yield {"__raw__": line} for unparseable lines."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                ev = {"__raw__": line[:200]}
            yield ev


def verify(path: str) -> dict:
    """Full chain verification. Returns {valid, events, errors}."""
    errors = []
    events = 0
    prev_hash = GENESIS
    prev_seq = 0
    known_seqs = set()
    for ev in iter_events(path):
        if not isinstance(ev, dict):
            errors.append({"seq": None, "error": "non-object JSON line"})
            continue
        if "__raw__" in ev:
            errors.append({"seq": None, "error": "unparseable line: %s..." % ev["__raw__"][:60]})
            continue
        events += 1
        seq = ev.get("seq")
        if not isinstance(seq, int):
            errors.append({"seq": seq, "error": "missing or non-integer seq"})
            continue
        if seq != prev_seq + 1:
            errors.append({"seq": seq, "error": "sequence gap or reorder: expected %d" % (prev_seq + 1)})
        if seq in known_seqs:
            errors.append({"seq": seq, "error": "duplicate seq"})
        known_seqs.add(seq)
        if ev.get("type") not in TYPES:
            errors.append({"seq": seq, "error": "unknown event type: %r" % ev.get("type")})
        if ev.get("prev_hash") != prev_hash:
            errors.append({"seq": seq, "error": "prev_hash mismatch (tampered, reordered, or deleted predecessor)"})
        if ev.get("hash") != event_hash(ev):
            errors.append({"seq": seq, "error": "hash mismatch (payload tampered after append)"})
        if ev.get("type") == "rollback":
            ref = ev.get("ref")
            if not isinstance(ref, int) or ref < 1 or ref >= seq:
                errors.append({"seq": seq, "error": "rollback ref %r does not point to an earlier event" % (ref,)})
        prev_hash = ev.get("hash") if isinstance(ev.get("hash"), str) else prev_hash
        prev_seq = seq if isinstance(seq, int) else prev_seq
    return {"valid": not errors, "events": events, "errors": errors}


def stats(path: str) -> dict:
    counts = {t: 0 for t in TYPES}
    total = 0
    for ev in iter_events(path):
        if isinstance(ev, dict) and ev.get("type") in counts:
            counts[ev["type"]] += 1
            total += 1
    return {"total": total, "by_type": counts}


def extract(path: str, etype: str) -> list:
    if etype not in TYPES:
        raise ValueError("unknown event type: %s" % etype)
    return [ev for ev in iter_events(path)
            if isinstance(ev, dict) and ev.get("type") == etype]
