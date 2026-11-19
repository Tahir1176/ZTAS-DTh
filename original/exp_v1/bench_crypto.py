"""
E3: Measured cost of the ZTAS-DTh provenance and identity primitives on a
commodity CPU: hash-chained provenance records, classical vs post-quantum
signatures (FIPS 204 ML-DSA, FIPS 205 SLH-DSA), classical vs PQ key
establishment (FIPS 203 ML-KEM), Merkle batching, and policy-decision latency.
"""
import json, sys, time, hashlib, os, statistics as st
import numpy as np
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519
from cryptography.hazmat.primitives import hashes
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, slh_dsa_sha2_128f
from pqcrypto.kem import ml_kem_768

REC = os.urandom(256)          # one provenance record (Sec. IV-D) ~256 B serialized


def timeit(fn, n):
    for _ in range(min(20, n)): fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); fn(); ts.append(time.perf_counter_ns() - t0)
    ts = np.array(ts) / 1e3   # microseconds
    return dict(median_us=float(np.median(ts)), p95_us=float(np.percentile(ts, 95)))


def sig_bench():
    out = {}
    sk = ed25519.Ed25519PrivateKey.generate(); pk = sk.public_key(); s = sk.sign(REC)
    out["Ed25519"] = dict(sign=timeit(lambda: sk.sign(REC), 3000),
                          verify=timeit(lambda: pk.verify(s, REC), 3000), sig_B=len(s), pk_B=32)
    sk2 = ec.generate_private_key(ec.SECP256R1()); pk2 = sk2.public_key()
    s2 = sk2.sign(REC, ec.ECDSA(hashes.SHA256()))
    out["ECDSA-P256"] = dict(sign=timeit(lambda: sk2.sign(REC, ec.ECDSA(hashes.SHA256())), 3000),
                             verify=timeit(lambda: pk2.verify(s2, REC, ec.ECDSA(hashes.SHA256())), 3000),
                             sig_B=len(s2), pk_B=64)
    for name, m, n in [("ML-DSA-44", ml_dsa_44, 3000), ("ML-DSA-65", ml_dsa_65, 3000),
                       ("SLH-DSA-SHA2-128f", slh_dsa_sha2_128f, 100)]:
        p, k = m.keygen(); sg = m.sign(k, REC)
        out[name] = dict(sign=timeit(lambda: m.sign(k, REC), n),
                         verify=timeit(lambda: m.verify(p, REC, sg), n),
                         sig_B=len(sg), pk_B=len(p))
    return out


def kem_bench():
    out = {}
    a = x25519.X25519PrivateKey.generate(); b = x25519.X25519PrivateKey.generate(); bp = b.public_key()
    out["X25519"] = dict(encaps=timeit(lambda: a.exchange(bp), 3000), ct_B=32, pk_B=32)
    p, k = ml_kem_768.keygen(); ct, ss = ml_kem_768.encaps(p)
    out["ML-KEM-768"] = dict(encaps=timeit(lambda: ml_kem_768.encaps(p), 3000),
                             decaps=timeit(lambda: ml_kem_768.decaps(k, ct), 3000),
                             ct_B=len(ct), pk_B=len(p))
    return out


def chain_bench():
    prev = b"\x00" * 32
    def step():
        nonlocal prev
        prev = hashlib.sha256(prev + REC).digest()
    return timeit(step, 20000)


def merkle_root(leaves):
    lv = [hashlib.sha256(b"\x00" + x).digest() for x in leaves]
    while len(lv) > 1:
        if len(lv) % 2: lv.append(lv[-1])
        lv = [hashlib.sha256(b"\x01" + lv[i] + lv[i + 1]).digest() for i in range(0, len(lv), 2)]
    return lv[0]


def batch_bench():
    p, k = ml_dsa_65.keygen(); out = []
    for B in [1, 4, 16, 64, 256, 1024]:
        recs = [os.urandom(256) for _ in range(B)]
        def f():
            r = merkle_root(recs); ml_dsa_65.sign(k, r)
        n = 300 if B <= 64 else 60
        t = timeit(f, n)
        out.append(dict(batch=B, total_us=t["median_us"], per_record_us=t["median_us"] / B,
                        records_per_s=1e6 * B / t["median_us"],
                        sig_bytes_per_record=3309 / B + 32 * int(np.ceil(np.log2(max(B, 1)))) ))
    return out


def policy_bench():
    w = np.array([0.10, 0.10, 0.35, 0.30, 0.15])
    rng = np.random.default_rng(0); r = rng.uniform(0, 100, 5)
    wl = list(w); rl = list(r)
    def decide():
        s = sum(a * b for a, b in zip(wl, rl))
        return 0 if s <= 30 else 1 if s <= 70 else 2 if s <= 90 else 3
    return timeit(decide, 50000)


if __name__ == "__main__":
    res = dict(sig=sig_bench(), kem=kem_bench(), chain=chain_bench(),
               batch=batch_bench(), policy=policy_bench())
    json.dump(res, open(sys.argv[1], "w"), indent=1)
    for k, v in res["sig"].items():
        print(k, round(v["sign"]["median_us"], 1), round(v["verify"]["median_us"], 1), v["sig_B"], v["pk_B"])
    print(res["kem"]); print("chain", res["chain"]); print("policy", res["policy"])
    for b in res["batch"]: print(b)
