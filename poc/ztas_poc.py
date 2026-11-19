"""
ZTAS-DTh controlled software proof-of-concept (revision v2, R6).

NOT an industrial deployment. All services run as separate OS processes on one host (localhost HTTP),
with simulated principals, artifacts and context. Purpose: show that the components compose into the
end-to-end workflow and measure software-level latency/resource overhead on a server CPU.

Services (one process each):
  idp      identity provider: issues short-lived Ed25519-signed tokens, revocation list
  pdp      policy decision point: 5-D risk score, tiers, decaying evidence counter, quarantine,
           human approval for safety-critical (operations-phase) assets
  seg      segmentation controller: purpose-bound flow segments with expiry
  prov     provenance service: per-gateway sequence numbers, hash chain, Merkle batches
           (odd-node promotion + leaf-count header), ML-DSA-65 batch signatures, SQLite ledger
  twin     digital-twin / MES endpoint (the protected resource)
  pep      policy enforcement point: token check -> segment check -> provenance & lineage check
           -> PDP decision -> forward; logs security events
Usage: python3 ztas_poc.py run ../data/raw/poc_results.json
"""
import json, os, sys, time, socket, hashlib, sqlite3, threading, base64, resource, http.client, statistics
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from multiprocessing import Process
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pqcrypto.sign import ml_dsa_65

PORTS = dict(idp=18101, pdp=18102, seg=18103, prov=18104, twin=18105, pep=18106)
H = lambda b: hashlib.sha256(b).digest()
b64 = lambda b: base64.b64encode(b).decode()
ub64 = lambda s: base64.b64decode(s)
KEYDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


# ------------------------------------------------------------------ helpers
class Client:
    def __init__(self, port):
        self.port = port; self.c = None
    def call(self, path, body=None):
        data = json.dumps(body or {}).encode()
        for attempt in range(2):
            try:
                if self.c is None:
                    self.c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10); self.c.connect()
                    self.c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.c.request("POST", path, data, {"Content-Type": "application/json"})
                r = self.c.getresponse(); return json.loads(r.read())
            except (ConnectionError, http.client.HTTPException, OSError):
                if self.c: self.c.close()
                self.c = None
                if attempt: raise


def serve(port, routes):
    class Hd(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def setup(self):
            super().setup(); self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
            fn = routes.get(self.path)
            out = fn(body) if fn else {"error": "no route"}
            data = json.dumps(out).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    routes["/stats"] = lambda b: dict(cpu_s=resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime,
                                      max_rss_kb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    ThreadingHTTPServer(("127.0.0.1", port), Hd).serve_forever()


# ------------------------------------------------------------------ IdP
def idp():
    sk = ed25519.Ed25519PrivateKey.generate()
    open(os.path.join(KEYDIR, "idp.pub"), "wb").write(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    revoked = set(); ROLE = {"eng01": ("human", "engineer", "D"), "cam01": ("service", "cam", "M"),
                             "plc07": ("device", "controller", "O"), "sup03": ("external", "supplier", "X"),
                             "adm01": ("human", "admin", "D")}
    def issue(b):
        p = b["principal"]
        if p not in ROLE: return {"error": "unknown"}
        t, role, ph = ROLE[p]
        claims = dict(sub=p, typ=t, role=role, phase=ph, exp=time.time() + 300, iat=time.time())
        raw = json.dumps(claims, sort_keys=True).encode()
        return {"token": b64(raw), "sig": b64(sk.sign(raw))}
    def revoke(b):
        revoked.add(b["principal"]); return {"ok": True}
    def crl(b): return {"revoked": sorted(revoked)}
    serve(PORTS["idp"], {"/issue": issue, "/revoke": revoke, "/crl": crl})


# ------------------------------------------------------------------ PDP
W = [0.10, 0.10, 0.35, 0.30, 0.15]; THETA = (30, 70, 90); KAPPA = 3.0; HALF_LIFE_S = 30.0
def pdp():
    ev = {}; quarantined = set(); pending = {}; lock = threading.Lock()
    def decide(b):
        p = b["sub"]; ctx = b["ctx"]
        with lock:
            if p in quarantined: return {"decision": "deny", "reason": "quarantined"}
            if p in pending: return {"decision": "deny", "reason": "isolation pending human approval"}
            r = sum(w * float(ctx.get(k, 0)) for w, k in zip(W, ["temporal", "spatial", "behavioural", "system", "business"]))
            e, t0 = ev.get(p, (0.0, time.time())); e *= 0.5 ** ((time.time() - t0) / HALF_LIFE_S)
            out = {"risk": r}
            if r > THETA[2]:
                tier = "isolate"
            elif r > THETA[1]:
                e += 2.0; tier = "block"
            elif r > THETA[0]:
                if ctx.get("stepup_ok", True):
                    e = max(0.0, e - 1.0); tier = "allow_after_stepup"
                elif ctx.get("known_outage", False):
                    tier = "deny_outage"      # failure during known outage is not counted as evidence
                else:
                    e += 1.0; tier = "deny_stepup_failed"
            else:
                tier = "allow"
            if tier != "isolate" and e >= KAPPA: tier = "isolate"
            ev[p] = (e, time.time())
            if tier == "isolate":
                if b.get("phase") == "O":
                    pending[p] = time.time(); out.update(decision="deny", reason="isolation requested; awaiting operator approval")
                else:
                    quarantined.add(p); out.update(decision="deny", reason="quarantined")
            else:
                out.update(decision="allow" if tier.startswith("allow") else "deny", reason=tier)
            out["evidence"] = e
            return out
    def approve(b):
        with lock:
            p = b["sub"]
            if p in pending and b.get("approver_role") == "admin":
                del pending[p]; quarantined.add(p); return {"ok": True}
            return {"ok": False}
    def status(b): return {"quarantined": sorted(quarantined), "pending": sorted(pending)}
    serve(PORTS["pdp"], {"/decide": decide, "/approve": approve, "/status": status})


# ------------------------------------------------------------------ Segmentation controller
def seg():
    segs = {}; lock = threading.Lock()
    def create(b):
        with lock:
            segs[b["id"]] = dict(flows=set(map(tuple, b["flows"])), principals=set(b["principals"]),
                                 purpose=b["purpose"], expires=time.time() + b["ttl_s"])
        return {"ok": True}
    def check(b):
        f = (b["src"], b["dst"]); now = time.time()
        with lock:
            for sid, s in segs.items():
                if f in s["flows"] and b["sub"] in s["principals"] and now < s["expires"]:
                    return {"ok": True, "segment": sid}
        return {"ok": False}
    serve(PORTS["seg"], {"/create": create, "/check": check})


# ------------------------------------------------------------------ Provenance service
BATCH_MAX, BATCH_TIMEOUT = 64, 0.05
def _levels(leaves):
    lv = [H(b"\x00" + x) for x in leaves]; L = [lv]
    while len(lv) > 1:
        nxt = [H(b"\x01" + lv[i] + lv[i + 1]) for i in range(0, len(lv) - 1, 2)]
        if len(lv) % 2: nxt.append(lv[-1])
        lv = nxt; L.append(lv)
    return L
def _proof(L, i):
    p = []
    for lv in L[:-1]:
        s = i ^ 1
        if s < len(lv): p.append([s < i, b64(lv[s])])
        i //= 2
    return p
def _header(n, root, gw, first_seq): return H(b"\x02" + n.to_bytes(4, "big") + root + gw.encode() + first_seq.to_bytes(8, "big"))

def prov():
    pk, sk = ml_dsa_65.keygen(); open(os.path.join(KEYDIR, "prov.pub"), "wb").write(pk)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("create table rec(id integer primary key, gw text, seq integer, body text, leaf blob, batch integer, idx integer)")
    db.execute("create table batch(id integer primary key, n integer, root blob, header blob, sig blob, gw text, first_seq integer)")
    lock = threading.Lock(); pending = []; seqs = {}; chain = {}; state = {"opened": None}
    def close_batch():
        if not pending: return
        leaves = [x[1] for x in pending]; L = _levels(leaves); gw = pending[0][2]; fs = pending[0][3]
        hd = _header(len(leaves), L[-1][0], gw, fs); sig = ml_dsa_65.sign(sk, hd)
        cur = db.execute("insert into batch(n,root,header,sig,gw,first_seq) values(?,?,?,?,?,?)", (len(leaves), L[-1][0], hd, sig, gw, fs))
        bid = cur.lastrowid
        for i, (rid, _, _, _) in enumerate(pending):
            db.execute("update rec set batch=?, idx=? where id=?", (bid, i, rid))
        db.commit(); pending.clear(); state["opened"] = None
    def ticker():
        while True:
            time.sleep(0.005)
            with lock:
                if state["opened"] and time.time() - state["opened"] > BATCH_TIMEOUT: close_batch()
    threading.Thread(target=ticker, daemon=True).start()
    def record(b):
        with lock:
            gw = b["gw"]; seqs[gw] = seqs.get(gw, 0) + 1; seq = seqs[gw]
            prev = chain.get(gw, "00" * 32)
            body = dict(b["record"], gw=gw, seq=seq, prev=prev, ts=time.time())
            raw = json.dumps(body, sort_keys=True).encode(); chain[gw] = H(prev.encode() + raw).hex()
            cur = db.execute("insert into rec(gw,seq,body,leaf) values(?,?,?,?)", (gw, seq, raw.decode(), raw))
            rid = cur.lastrowid
            if not pending: state["opened"] = time.time()
            pending.append((rid, raw, gw, seq))
            if len(pending) >= BATCH_MAX: close_batch()
            return {"id": rid, "seq": seq}
    def get_proof(b):
        with lock:
            r = db.execute("select body,batch,idx from rec where id=?", (b["id"],)).fetchone()
            if not r or r[1] is None: return {"ready": False}
            body, bid, idx = r
            leaves = [x[0] for x in db.execute("select leaf from rec where batch=? order by idx", (bid,))]
            n, root, hd, sig, gw, fs = db.execute("select n,root,header,sig,gw,first_seq from batch where id=?", (bid,)).fetchone()
            return dict(ready=True, body=body, proof=_proof(_levels(leaves), idx), n=n, root=b64(root), gw=gw, first_seq=fs,
                        sig=b64(sig), batch=bid)
    def flush(b):
        with lock: close_batch()
        return {"ok": True}
    serve(PORTS["prov"], {"/record": record, "/proof": get_proof, "/flush": flush})


# ------------------------------------------------------------------ Twin
def twin():
    state = {"applied": 0}
    def apply(b):
        state["applied"] += 1; return {"ok": True, "applied": state["applied"]}
    serve(PORTS["twin"], {"/apply": apply})


# ------------------------------------------------------------------ PEP
LINEAGE = {   # artifact type -> (allowed actor roles, required parent type or None)
    "design_rev": ({"engineer"}, None),
    "machine_instructions": ({"cam"}, "design_rev"),
    "component_firmware": ({"supplier"}, None),
    "sensor_batch": ({"controller"}, None),
}
def pep():
    idp_pub = ed25519.Ed25519PublicKey.from_public_bytes(open(os.path.join(KEYDIR, "idp.pub"), "rb").read())
    prov_pub = open(os.path.join(KEYDIR, "prov.pub"), "rb").read()
    C = {k: Client(PORTS[k]) for k in ["idp", "pdp", "seg", "prov", "twin"]}
    lock = threading.Lock(); last_seq = {}; verified_batches = {}; crl = {"set": set(), "t": 0.0}; events = []
    CRL_REFRESH_S = 1.0
    def log(kind, **kw):
        events.append(dict(t=time.time(), kind=kind, **kw))
    def verify_artifact(art, sub_role):
        pr = C["prov"].call("/proof", {"id": art["record_id"]})
        if not pr.get("ready"): return False, "provenance not yet anchored"
        body = json.loads(pr["body"])
        if body["artifact_hash"] != hashlib.sha256(ub64(art["content"])).hexdigest(): return False, "content hash mismatch (post-signing alteration)"
        # Merkle inclusion
        h = H(b"\x00" + pr["body"].encode())
        for left, s in pr["proof"]:
            s = ub64(s); h = H(b"\x01" + s + h) if left else H(b"\x01" + h + s)
        if h != ub64(pr["root"]): return False, "inclusion proof invalid"
        hd = _header(pr["n"], h, pr["gw"], pr["first_seq"])
        key = (pr["batch"], b64(hd))
        if key not in verified_batches:
            try:
                ml_dsa_65.verify(prov_pub, hd, ub64(pr["sig"])); verified_batches[key] = True
            except Exception:
                return False, "batch signature invalid"
        # freshness / replay: strictly increasing sequence per gateway at this gate
        with lock:
            if body["seq"] <= last_seq.get(body["gw"], 0): return False, "replayed or reordered record"
            last_seq[body["gw"]] = body["seq"]
        roles, parent_t = LINEAGE.get(body["type"], (set(), None))
        if body["actor_role"] not in roles: return False, "lineage policy: actor role not authorised"
        if parent_t:
            pp = C["prov"].call("/proof", {"id": body.get("parent")}) if body.get("parent") else {"ready": False}
            if not pp.get("ready") or json.loads(pp["body"])["type"] != parent_t or json.loads(pp["body"]).get("status") != "released":
                return False, "lineage policy: missing or unreleased parent"
        return True, "ok"
    def handle(b):
        T = {}; t0 = time.perf_counter()
        raw = ub64(b["token"])
        try:
            idp_pub.verify(ub64(b["sig"]), raw)
        except Exception:
            log("deny", reason="bad token"); return {"decision": "deny", "reason": "bad token"}
        cl = json.loads(raw)
        if cl["exp"] < time.time(): return {"decision": "deny", "reason": "token expired"}
        if time.time() - crl["t"] > CRL_REFRESH_S:
            crl["set"] = set(C["idp"].call("/crl")["revoked"]); crl["t"] = time.time()
        if cl["sub"] in crl["set"]:
            log("deny", sub=cl["sub"], reason="revoked"); return {"decision": "deny", "reason": "identity revoked"}
        T["token_us"] = (time.perf_counter() - t0) * 1e6; t1 = time.perf_counter()
        s = C["seg"].call("/check", {"src": b["src"], "dst": b["dst"], "sub": cl["sub"]})
        T["segment_us"] = (time.perf_counter() - t1) * 1e6
        if not s["ok"]:
            log("deny", sub=cl["sub"], reason="no active segment"); return {"decision": "deny", "reason": "no active segment", "timing": T}
        if b.get("artifact"):
            t2 = time.perf_counter(); ok, why = verify_artifact(b["artifact"], cl["role"]); T["provenance_us"] = (time.perf_counter() - t2) * 1e6
            if not ok:
                log("deny", sub=cl["sub"], reason=why); return {"decision": "deny", "reason": why, "timing": T}
        t3 = time.perf_counter()
        try:
            d = C["pdp"].call("/decide", {"sub": cl["sub"], "phase": cl["phase"], "ctx": b.get("ctx", {})})
        except Exception:
            log("deny", sub=cl["sub"], reason="PDP unavailable (fail-closed)")
            return {"decision": "deny", "reason": "PDP unavailable: fail-closed", "timing": T}
        T["pdp_us"] = (time.perf_counter() - t3) * 1e6
        if d["decision"] != "allow":
            log("deny", sub=cl["sub"], reason=d["reason"], risk=d.get("risk")); return dict(d, timing=T)
        t4 = time.perf_counter(); C["twin"].call("/apply", {"from": cl["sub"]}); T["forward_us"] = (time.perf_counter() - t4) * 1e6
        T["pep_total_us"] = (time.perf_counter() - t0) * 1e6
        return dict(d, timing=T)
    def get_events(b): return {"events": events[-200:], "n": len(events)}
    serve(PORTS["pep"], {"/request": handle, "/events": get_events})


# ------------------------------------------------------------------ scenario driver
def token(idp_c, p):
    t = idp_c.call("/issue", {"principal": p}); return t["token"], t["sig"]

def make_artifact(prov_c, gw, typ, actor, role, content, parent=None, status=None):
    rec = dict(type=typ, actor=actor, actor_role=role, artifact_hash=hashlib.sha256(content).hexdigest())
    if parent: rec["parent"] = parent
    if status: rec["status"] = status
    r = prov_c.call("/record", {"gw": gw, "record": rec})
    return {"record_id": r["id"], "content": b64(content)}

def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(q / 100 * len(xs)))]

def run(out):
    os.makedirs(KEYDIR, exist_ok=True)
    procs = {}
    for name, fn in [("idp", idp), ("prov", prov), ("pdp", pdp), ("seg", seg), ("twin", twin)]:
        procs[name] = Process(target=fn, daemon=True); procs[name].start()
    time.sleep(1.5)
    procs["pep"] = Process(target=pep, daemon=True); procs["pep"].start(); time.sleep(1.0)
    C = {k: Client(PORTS[k]) for k in PORTS}
    R = {"scenarios": {}, "note": "controlled software proof-of-concept on one host; not an industrial deployment"}
    now_ctx = dict(temporal=10, spatial=10, behavioural=12, system=10, business=20)
    C["seg"].call("/create", {"id": "s-design-to-mes", "flows": [["D", "M"]], "principals": ["cam01", "sup03", "eng01"], "purpose": "release", "ttl_s": 600})
    C["seg"].call("/create", {"id": "s-telemetry", "flows": [["O", "O"]], "principals": ["plc07"], "purpose": "telemetry", "ttl_s": 600})
    tk = {p: token(C["idp"], p) for p in ["eng01", "cam01", "plc07", "sup03"]}
    def req(p, src, dst, art=None, ctx=None):
        t0 = time.perf_counter()
        r = C["pep"].call("/request", {"token": tk[p][0], "sig": tk[p][1], "src": src, "dst": dst, "artifact": art, "ctx": ctx or now_ctx})
        r["client_us"] = (time.perf_counter() - t0) * 1e6; return r
    # design released by engineer, instructions derived by CAM service
    design = make_artifact(C["prov"], "gw-D", "design_rev", "eng01", "engineer", b"CAD rev B", status="released")
    C["prov"].call("/flush")
    # S1 legitimate workflow: N requests, each with a fresh instructions artifact (fresh sequence number)
    arts = []
    for i in range(1000):
        arts.append(make_artifact(C["prov"], "gw-M", "machine_instructions", "cam01", "cam", f"G-code {i}".encode(), parent=design["record_id"]))
    C["prov"].call("/flush"); time.sleep(0.1)
    lat = []; parts = {}
    for a in arts:
        r = req("cam01", "D", "M", a); assert r["decision"] == "allow", r
        lat.append(r["client_us"])
        for k, v in r["timing"].items(): parts.setdefault(k, []).append(v)
    base = []
    for _ in range(1000):
        t0 = time.perf_counter(); C["twin"].call("/apply", {}); base.append((time.perf_counter() - t0) * 1e6)
    noart = []
    for _ in range(1000):
        r = req("plc07", "O", "O"); noart.append(r["client_us"]); assert r["decision"] == "allow", r
    summ = lambda xs: dict(n=len(xs), median_us=statistics.median(xs), p95_us=pct(xs, 95), p99_us=pct(xs, 99), mean_us=statistics.mean(xs))
    R["latency"] = dict(end_to_end_with_artifact=summ(lat), end_to_end_no_artifact=summ(noart), direct_to_twin_baseline=summ(base),
                        components={k: summ(v) for k, v in parts.items()})
    # S2 post-signing alteration
    a = make_artifact(C["prov"], "gw-M", "machine_instructions", "cam01", "cam", b"G-code good", parent=design["record_id"]); C["prov"].call("/flush")
    bad = dict(a, content=b64(b"G-code TAMPERED")); R["scenarios"]["S2_post_signing_alteration"] = req("cam01", "D", "M", bad)
    # S3 replay of an already-accepted record
    R["scenarios"]["S3_replay"] = req("cam01", "D", "M", arts[10])
    # S4 lineage violation: instructions derived from an unreleased design
    d2 = make_artifact(C["prov"], "gw-D", "design_rev", "eng01", "engineer", b"CAD rev C draft", status="draft"); C["prov"].call("/flush")
    a4 = make_artifact(C["prov"], "gw-M", "machine_instructions", "cam01", "cam", b"G-code from draft", parent=d2["record_id"]); C["prov"].call("/flush")
    R["scenarios"]["S4_lineage_unreleased_parent"] = req("cam01", "D", "M", a4)
    # S4b: wrong actor role signs instructions (compromised engineer identity)
    a4b = make_artifact(C["prov"], "gw-M", "machine_instructions", "eng01", "engineer", b"G-code by engineer", parent=design["record_id"]); C["prov"].call("/flush")
    R["scenarios"]["S4b_lineage_wrong_actor_role"] = req("eng01", "D", "M", a4b)
    # S5 validly signed malicious supplier firmware (LIMITATION: accepted by provenance + lineage)
    a5 = make_artifact(C["prov"], "gw-X", "component_firmware", "sup03", "supplier", b"firmware with backdoor"); C["prov"].call("/flush")
    R["scenarios"]["S5_validly_signed_malicious_supplier_artifact"] = req("sup03", "D", "M", a5)
    # S6 compromised device: anomalous context with failed step-ups -> evidence -> isolation request (operations phase -> approval)
    seq = []
    for i in range(6):
        r = req("plc07", "O", "O", ctx=dict(temporal=40, spatial=30, behavioural=60, system=55, business=20, stepup_ok=False))
        seq.append({k: r.get(k) for k in ["decision", "reason", "risk", "evidence"]})
    R["scenarios"]["S6_compromised_device_sequence"] = seq
    R["scenarios"]["S6_status_before_approval"] = C["pdp"].call("/status")
    C["pdp"].call("/approve", {"sub": "plc07", "approver_role": "admin"})
    R["scenarios"]["S6_status_after_approval"] = C["pdp"].call("/status")
    R["scenarios"]["S6_request_after_quarantine"] = req("plc07", "O", "O")
    # S8 expired segment (segment s-short had a 0.5 s lifetime)
    C["seg"].call("/create", {"id": "s-short", "flows": [["S", "D"]], "principals": ["eng01"], "purpose": "feedback", "ttl_s": 0.5})
    R["scenarios"]["S8a_segment_active"] = req("eng01", "S", "D")
    time.sleep(0.6)
    R["scenarios"]["S8b_segment_expired"] = req("eng01", "S", "D")
    # S7 revocation propagation delay
    C["idp"].call("/revoke", {"principal": "eng01"}); t0 = time.time(); n = 0
    while True:
        r = req("eng01", "D", "M"); n += 1
        if r["reason"] == "identity revoked": break
        time.sleep(0.05)
    R["scenarios"]["S7_revocation"] = dict(final=r["reason"], propagation_delay_s=time.time() - t0, requests_until_effective=n,
                                           note="bounded by PEP revocation-list refresh interval (1 s in PoC)")
    # S9 PDP failure -> fail-closed
    procs["pdp"].terminate(); procs["pdp"].join(); time.sleep(0.3)
    a9 = make_artifact(C["prov"], "gw-M", "machine_instructions", "cam01", "cam", b"G-code x", parent=design["record_id"]); C["prov"].call("/flush")
    R["scenarios"]["S9_pdp_unavailable"] = req("cam01", "D", "M", a9)
    # resources
    R["resources"] = {k: C[k].call("/stats") for k in ["idp", "seg", "prov", "twin", "pep"]}
    R["events_logged"] = C["pep"].call("/events")["n"]
    for k, p in procs.items():
        if p.is_alive(): p.terminate()
    for sc in R["scenarios"].values():
        if isinstance(sc, dict): sc.pop("timing", None)
    json.dump(R, open(out, "w"), indent=1)
    print(json.dumps({k: v for k, v in R.items() if k != "latency"}, indent=1)[:4000])
    print(json.dumps(R["latency"], indent=1))


if __name__ == "__main__":
    run(sys.argv[2])
