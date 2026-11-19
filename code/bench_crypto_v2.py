"""
E3 (revision v2): cryptographic micro-benchmarks with full statistics and raw samples.
Changes vs v1 (audit C13, C15, C16): raw samples saved; mean/sd/median/p5/p95/p99 reported;
inclusion-proof generation and verification measured; Merkle construction fixed (odd-node
promotion + signed leaf count); environment recorded; no outlier removal (medians are robust).
Measured on a server-class CPU - NOT representative of edge gateways or HSMs.

Usage: python3 bench_crypto_v2.py ../data/raw/e3_crypto_v2.json ../data/raw/e3_crypto_samples.npz
"""
import json, sys, os, time, hashlib, platform, subprocess
import numpy as np
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87, slh_dsa_sha2_128f
from pqcrypto.kem import ml_kem_768

SAMPLES = {}
REC = os.urandom(256)


def bench(name, fn, n, warm=50):
    for _ in range(warm): fn()
    ts = np.empty(n)
    for i in range(n):
        t0 = time.perf_counter_ns(); fn(); ts[i] = time.perf_counter_ns() - t0
    ts /= 1e3
    SAMPLES[name] = ts
    return dict(n=n, warmup=warm, mean_us=float(ts.mean()), sd_us=float(ts.std(ddof=1)), median_us=float(np.median(ts)),
                p5_us=float(np.percentile(ts, 5)), p95_us=float(np.percentile(ts, 95)), p99_us=float(np.percentile(ts, 99)))


H = lambda b: hashlib.sha256(b).digest()


def leaf(x): return H(b"\x00" + x)


def build_levels(leaves):
    lv = [leaf(x) for x in leaves]; levels = [lv]
    while len(lv) > 1:
        nxt = [H(b"\x01" + lv[i] + lv[i + 1]) for i in range(0, len(lv) - 1, 2)]
        if len(lv) % 2: nxt.append(lv[-1])          # promote odd node (no duplication)
        lv = nxt; levels.append(lv)
    return levels


def header(n, root): return H(b"\x02" + n.to_bytes(4, "big") + root)   # signed: binds leaf count


def proof(levels, i):
    p = []
    for lv in levels[:-1]:
        sib = i ^ 1
        if sib < len(lv): p.append((sib < i, lv[sib]))
        i //= 2
    return p


def verify_proof(x, p, root):
    h = leaf(x)
    for left, s in p:
        h = H(b"\x01" + s + h) if left else H(b"\x01" + h + s)
    return h == root


def env():
    cpu = subprocess.run(["bash", "-c", "lscpu | grep -E 'Model name|^CPU\\(s\\)|MHz|L2|L3' "], capture_output=True, text=True).stdout
    mem = subprocess.run(["bash", "-c", "grep MemTotal /proc/meminfo"], capture_output=True, text=True).stdout
    return dict(platform=platform.platform(), python=platform.python_version(), cryptography=cryptography.__version__,
                pqcrypto="1.0.0 (pip); shared library contains no AVX2 symbol names -> presumed portable implementation (unverified)",
                cpu=cpu.strip(), mem=mem.strip(), timer="time.perf_counter_ns, single thread", outliers="none removed")


def main(out_json, out_npz):
    R = dict(env=env(), sig={}, kem={}, hash={}, merkle=[])
    sk = ed25519.Ed25519PrivateKey.generate(); pk = sk.public_key(); s = sk.sign(REC)
    R["sig"]["Ed25519"] = dict(sign=bench("ed_sign", lambda: sk.sign(REC), 5000), verify=bench("ed_ver", lambda: pk.verify(s, REC), 5000),
                               sig_B=len(s), pk_B=len(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
    sk2 = ec.generate_private_key(ec.SECP256R1()); pk2 = sk2.public_key(); s2 = sk2.sign(REC, ec.ECDSA(hashes.SHA256()))
    R["sig"]["ECDSA-P256"] = dict(sign=bench("ec_sign", lambda: sk2.sign(REC, ec.ECDSA(hashes.SHA256())), 5000),
                                  verify=bench("ec_ver", lambda: pk2.verify(s2, REC, ec.ECDSA(hashes.SHA256())), 5000),
                                  sig_B=len(s2), pk_B=len(pk2.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)))
    for name, m, n in [("ML-DSA-44", ml_dsa_44, 2000), ("ML-DSA-65", ml_dsa_65, 2000), ("ML-DSA-87", ml_dsa_87, 1000),
                       ("SLH-DSA-SHA2-128f", slh_dsa_sha2_128f, 100)]:
        p, k = m.keygen(); sg = m.sign(k, REC)
        R["sig"][name] = dict(sign=bench(name + "_sign", lambda: m.sign(k, REC), n, warm=10),
                              verify=bench(name + "_ver", lambda: m.verify(p, REC, sg), n, warm=10),
                              keygen=bench(name + "_keygen", lambda: m.keygen(), min(n, 200), warm=5),
                              sig_B=len(sg), pk_B=len(p))
    a = x25519.X25519PrivateKey.generate(); bp = x25519.X25519PrivateKey.generate().public_key()
    R["kem"]["X25519"] = dict(exchange=bench("x25519", lambda: a.exchange(bp), 5000), ct_B=32, pk_B=32)
    p, k = ml_kem_768.keygen(); ct, ss = ml_kem_768.encaps(p)
    R["kem"]["ML-KEM-768"] = dict(keygen=bench("kem_kg", lambda: ml_kem_768.keygen(), 2000), encaps=bench("kem_enc", lambda: ml_kem_768.encaps(p), 5000),
                                  decaps=bench("kem_dec", lambda: ml_kem_768.decaps(k, ct), 5000), ct_B=len(ct), pk_B=len(p))
    prev = [b"\x00" * 32]
    def chain():
        prev[0] = H(prev[0] + REC)
    R["hash"]["sha256_chain_256B"] = bench("chain", chain, 50000)
    R["hash"]["sha256_leaf_256B"] = bench("leaf", lambda: leaf(REC), 50000)
    p65, k65 = ml_dsa_65.keygen()
    for B in [1, 4, 16, 64, 256, 1024, 4096]:
        recs = [os.urandom(256) for _ in range(B)]
        n = 200 if B <= 256 else 40
        def build_sign():
            lv = build_levels(recs); hd = header(B, lv[-1][0]); return ml_dsa_65.sign(k65, hd)
        lv = build_levels(recs); hd = header(B, lv[-1][0]); sig = ml_dsa_65.sign(k65, hd)
        t_bs = bench(f"merkle_sign_{B}", build_sign, n, warm=5)
        t_tree = bench(f"merkle_tree_{B}", lambda: build_levels(recs), n, warm=5)
        idx = B // 2
        t_pg = bench(f"proof_gen_{B}", lambda: proof(lv, idx), 2000, warm=20)
        pr = proof(lv, idx)
        assert verify_proof(recs[idx], pr, lv[-1][0])
        t_pv = bench(f"proof_ver_{B}", lambda: verify_proof(recs[idx], pr, lv[-1][0]), 2000, warm=20)
        t_sv = bench(f"batch_sig_ver_{B}", lambda: ml_dsa_65.verify(p65, hd, sig), 500, warm=10)
        R["merkle"].append(dict(batch=B, build_and_sign=t_bs, tree_only=t_tree, proof_gen=t_pg, proof_verify=t_pv,
                                batch_sig_verify=t_sv, proof_hashes=len(pr),
                                sign_per_record_us=t_bs["median_us"] / B,
                                verify_per_record_us_independent=t_pv["median_us"] + t_sv["median_us"],
                                verify_per_record_us_batch=(t_sv["median_us"] + B * t_pv["median_us"]) / B,
                                authenticator_B_per_record=len(sig) / B + 32 * len(pr) + 4 / B))
    json.dump(R, open(out_json, "w"), indent=1)
    np.savez_compressed(out_npz, **SAMPLES)
    for k_, v in R["sig"].items():
        print(k_, round(v["sign"]["median_us"], 1), round(v["verify"]["median_us"], 1), v["sig_B"], v["pk_B"])
    for m in R["merkle"]:
        print(m["batch"], round(m["sign_per_record_us"], 2), round(m["verify_per_record_us_independent"], 1),
              round(m["verify_per_record_us_batch"], 2), round(m["authenticator_B_per_record"], 1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
