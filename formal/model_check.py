"""
Bounded explicit-state model checking of ZTAS-DTh security properties (revision v2).

Tooling note: the TLA+ tools (TLC) could not be downloaded in the revision environment, so this
purpose-written breadth-first explicit-state checker is used instead. It enumerates EVERY reachable
state of small, bounded models and checks invariants in each state. It is bounded verification of an
abstract model, not a proof for unbounded systems, and not a verification of an implementation.
Equivalent TLA+ specifications are provided in this folder for independent checking with TLC.

Models
  M1  provenance gate: gateway signing, adversary (tamper, replay, reorder, drop, inject, key
      compromise), revocation, verifier with sequence/freshness and epoch checks.
  M2  policy enforcement: segments, per-request decisions, isolation, control-plane separation.
  M3  Merkle batch encoding: exhaustive search for distinct leaf lists with equal roots.
Each model is checked in the intended configuration and in NEGATIVE-CONTROL configurations in which a
check is removed; a negative control must produce a counterexample, otherwise the model is vacuous.

Usage: python3 model_check.py > logs/model_check.log
"""
import hashlib, itertools, json, sys, time
from collections import deque

# ---------------------------------------------------------------- generic BFS checker
def bfs(init, succ, invariants, max_states=5_000_000):
    seen = {init}; q = deque([init]); parent = {init: None}; n = 0
    while q:
        s = q.popleft(); n += 1
        for name, inv in invariants.items():
            if not inv(s):
                trace = []
                while s is not None:
                    trace.append(s); s = parent[s]
                return dict(result="VIOLATION", invariant=name, states=n, trace=list(reversed(trace)))
        for label, t in succ(s):
            if t not in seen:
                seen.add(t); parent[t] = s; q.append(t)
                if len(seen) > max_states:
                    return dict(result="BOUND_EXCEEDED", states=n)
    return dict(result="OK", states=n, distinct=len(seen))


# ---------------------------------------------------------------- M1 provenance gate
# message = (seq, payload, epoch, sigvalid, authentic)
#   payload: 'g' genuine content for seq, 'b' attacker content
#   sigvalid: signature verifies under key of `epoch`
#   authentic: produced by the honest gateway (ground truth, invisible to the verifier)
# state = (next_seq, channel(frozenset msgs), key_comp(bool), revoked(frozenset epochs), epoch,
#          last_acc, accepted(tuple of msgs), alarm(bool))
def m1(N=3, check_seq=True, check_sig=True, check_revocation=True, allow_key_compromise=True, strict_gap=True):
    init = (1, frozenset(), False, frozenset(), 0, 0, (), False)

    def succ(s):
        nxt, ch, kc, rev, ep, last, acc, alarm = s
        out = []
        if nxt <= N:   # honest gateway signs record nxt
            out.append(("sign", (nxt + 1, ch | {(nxt, "g", ep, True, True)}, kc, rev, ep, last, acc, alarm)))
        for m in ch:
            seq, pl, e, sv, au = m
            # adversary tampers: content changes; signature only re-computable if key compromised
            if pl == "g":
                out.append(("tamper", (nxt, (ch - {m}) | {(seq, "b", e, kc and e == ep, False)}, kc, rev, ep, last, acc, alarm)))
            out.append(("drop", (nxt, ch - {m}, kc, rev, ep, last, acc, alarm)))
            # verifier processes m (channel is a set => any order; message stays => replay possible)
            ok = True
            if check_sig and not sv: ok = False
            if check_revocation and e in rev: ok = False
            if check_seq:
                if seq <= last: ok = False                       # replay / reordering
                if strict_gap and seq != last + 1:               # gap => hold and alarm
                    out.append(("gap_alarm", (nxt, ch, kc, rev, ep, last, acc, True)))
                    ok = False
            if ok:
                out.append(("accept", (nxt, ch, kc, rev, ep, max(last, seq), acc + (m,), alarm)))
        if allow_key_compromise and not kc:
            out.append(("key_compromise", (nxt, ch, True, rev, ep, last, acc, alarm)))
        if kc:
            # attacker injects arbitrary signed content under the compromised epoch
            for seq in range(1, N + 1):
                if (seq, "b", ep, True, False) not in ch:
                    out.append(("inject", (nxt, ch | {(seq, "b", ep, True, False)}, kc, rev, ep, last, acc, alarm)))
            if ep not in rev and ep < 1:   # detection -> revoke epoch, rekey (new uncompromised key)
                out.append(("revoke_rekey", (nxt, ch, False, rev | {ep}, ep + 1, last, acc, alarm)))
        return out

    def integrity(s):            # every accepted record is authentic
        return all(m[4] for m in s[6])

    def integrity_after_revocation(s):   # nothing signed under a revoked epoch is accepted after revocation
        return True  # checked via trace replay below (see m1_revocation)

    def no_replay(s):
        seqs = [m[0] for m in s[6]]
        return len(seqs) == len(set(seqs))

    def order(s):
        seqs = [m[0] for m in s[6]]
        return all(a < b for a, b in zip(seqs, seqs[1:]))

    return init, succ, dict(integrity=integrity, no_replay=no_replay, order=order)


def m1_revocation_property(N=2, check_revocation=True):
    """Revocation enforcement: once epoch e is revoked, no message of epoch e is accepted later.
    State is extended with the set of epochs revoked BEFORE each acceptance (recorded per accept)."""
    init, succ0, _ = m1(N=N, check_revocation=check_revocation)
    def succ(s):
        base, viol = s
        for label, t in succ0(base):
            v = viol
            if label == "accept":
                m = t[6][-1]
                if m[2] in base[3]:
                    v = True
            yield label, (t, v)
    return (init, False), succ, dict(revocation_enforced=lambda s: not s[1])


# ---------------------------------------------------------------- M2 policy enforcement (PEP/PDP)
# principals: 'eng' (legitimate), 'dev' (becomes compromised), 'adm' (control-plane administrator)
# state = (seg_open, isolated(frozenset), comp(bool), cache(frozenset principals with cached allow),
#          delivered(tuple of (principal, seg_open_at_delivery, isolated_at_delivery)), policy_owner_changes(tuple))
def m2(continuous=True, enforce_plane_separation=True, max_deliv=3):
    init = (False, frozenset(), False, frozenset(), (), ())
    P = ("eng", "dev")

    def succ(s):
        seg, iso, comp, cache, deliv, pol = s
        out = [("seg_toggle", (not seg, iso, comp, frozenset() if seg else cache, deliv, pol))]
        if not comp:
            out.append(("compromise_dev", (seg, iso, True, cache, deliv, pol)))
        if comp and "dev" not in iso:
            out.append(("isolate_dev", (seg, iso | {"dev"}, comp, cache, deliv, pol)))
        if len(deliv) < max_deliv:
            for p in P:
                if continuous:
                    allow = seg and p not in iso
                else:  # negative control: decision cached at session start, not re-evaluated
                    allow = (p in cache) or (seg and p not in iso)
                if allow:
                    out.append(("deliver_" + p, (seg, iso, comp, cache | {p}, deliv + ((p, seg, p in iso),), pol)))
        # control-plane: data-plane principals request a policy change
        if len(pol) < 1:
            for p in P:
                if (not enforce_plane_separation) or p == "adm":
                    out.append(("policy_change_" + p, (seg, iso, comp, cache, deliv, pol + (p,))))
            out.append(("policy_change_adm", (seg, iso, comp, cache, deliv, pol + ("adm",))))
        return out

    inv = dict(
        flow_authorisation=lambda s: all(d[1] for d in s[4]),
        containment_after_isolation=lambda s: all(not d[2] for d in s[4]),
        plane_separation=lambda s: all(p == "adm" for p in s[5]),
    )
    return init, succ, inv


# ---------------------------------------------------------------- M3 Merkle encoding
def H(b): return hashlib.sha256(b).digest()

def root_v1(leaves):
    lv = [H(b"\x00" + x) for x in leaves]
    while len(lv) > 1:
        if len(lv) % 2: lv.append(lv[-1])
        lv = [H(b"\x01" + lv[i] + lv[i + 1]) for i in range(0, len(lv), 2)]
    return lv[0]

def root_v2(leaves):
    """Fix: promote (not duplicate) an odd node, and sign a header binding the leaf count."""
    lv = [H(b"\x00" + x) for x in leaves]
    while len(lv) > 1:
        nxt = [H(b"\x01" + lv[i] + lv[i + 1]) for i in range(0, len(lv) - 1, 2)]
        if len(lv) % 2: nxt.append(lv[-1])
        lv = nxt
    return H(b"\x02" + len(leaves).to_bytes(4, "big") + lv[0])

def m3(rootfn, alphabet=(b"a", b"b", b"c"), maxlen=5):
    seen = {}; n = 0
    for L in range(1, maxlen + 1):
        for leaves in itertools.product(alphabet, repeat=L):
            n += 1; r = rootfn(list(leaves))
            if r in seen and seen[r] != leaves:
                return dict(result="VIOLATION", invariant="distinct_lists_distinct_roots",
                            states=n, trace=[[x.decode() for x in seen[r]], [x.decode() for x in leaves]])
            seen[r] = leaves
    return dict(result="OK", states=n)


# ---------------------------------------------------------------- run all
def fmt_trace(tr, maxlen=12):
    return [str(x) for x in tr[:maxlen]]

if __name__ == "__main__":
    runs = []
    def rec(model, cfg, expect, res):
        res = dict(res); tr = res.pop("trace", None)
        ok = (res["result"] == "OK") == (expect == "OK")
        runs.append(dict(model=model, config=cfg, expected=expect, **res, matches_expectation=ok,
                         counterexample=fmt_trace(tr) if tr else None))
        print(f"[{model}] {cfg}: {res['result']} {res.get('invariant','')} states={res.get('states')} "
              f"expected={expect} -> {'PASS' if ok else 'UNEXPECTED'}", flush=True)
        if tr:
            for x in fmt_trace(tr): print("    ", x)

    t0 = time.time()
    # M1: intended configuration, no key compromise
    i, s, inv = m1(N=3, allow_key_compromise=False); rec("M1", "full checks, key never compromised", "OK", bfs(i, s, inv))
    # M1: key compromise allowed -> integrity is NOT guaranteed (documents the assumption)
    i, s, inv = m1(N=2, allow_key_compromise=True); rec("M1", "full checks, key compromise allowed (assumption violated)", "VIOLATION", bfs(i, s, {"integrity": inv["integrity"]}))
    i, s, inv = m1(N=2, allow_key_compromise=True); rec("M1", "full checks, key compromise allowed: replay/order", "OK", bfs(i, s, {"no_replay": inv["no_replay"], "order": inv["order"]}))
    # negative controls
    i, s, inv = m1(N=3, check_seq=False, allow_key_compromise=False); rec("M1", "NEG: no sequence check", "VIOLATION", bfs(i, s, {"no_replay": inv["no_replay"]}))
    i, s, inv = m1(N=3, check_sig=False, allow_key_compromise=False); rec("M1", "NEG: no signature check", "VIOLATION", bfs(i, s, {"integrity": inv["integrity"]}))
    # revocation enforcement
    i, s, inv = m1_revocation_property(N=2, check_revocation=True); rec("M1", "revocation enforcement", "OK", bfs(i, s, inv))
    i, s, inv = m1_revocation_property(N=2, check_revocation=False); rec("M1", "NEG: no revocation check", "VIOLATION", bfs(i, s, inv))
    # M2
    i, s, inv = m2(); rec("M2", "continuous evaluation + plane separation", "OK", bfs(i, s, inv))
    i, s, inv = m2(continuous=False); rec("M2", "NEG: cached session decision", "VIOLATION", bfs(i, s, inv))
    i, s, inv = m2(enforce_plane_separation=False); rec("M2", "NEG: data-plane principals may change policy", "VIOLATION", bfs(i, s, inv))
    # M3
    rec("M3", "v1 Merkle (odd-node duplication, no length binding)", "VIOLATION", m3(root_v1))
    rec("M3", "v2 Merkle (odd-node promotion + signed leaf count)", "OK", m3(root_v2))
    print(f"total time {time.time()-t0:.1f}s")
    json.dump(runs, open(sys.argv[1] if len(sys.argv) > 1 else "logs/model_check_results.json", "w"), indent=1, default=str)
