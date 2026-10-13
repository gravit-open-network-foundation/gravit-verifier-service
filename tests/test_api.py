"""End-to-end test against a running API: python3 tests/test_api.py <base_url> <api_key> <golden_vectors.json>"""
import copy, json, sys
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "sdk", "python"))
from gravit_verifier_client import ApiError, Client, verify_export, verify_response

base, key, vectors_path = sys.argv[1:4]
gv = Client(key, base)
vectors = {v["name"]: v for v in json.load(open(vectors_path))}
kd = gv.service_key()
ok = 0
for name in ["committed_two_strong", "result_false_contradicts", "two_keys_one_operator", "no_registry_caps_at_prob"]:
    v = vectors[name]
    art = {"artifact_id": v["name"], "claimed_state": v["claimed_state"], "context": v["context"], "evidence": v["evidence"]}
    res = gv.verify(art, use_test_registry=v["use_registry"])
    got = res["result"]["decision"]
    assert got == v["expected"], f"{name}: decision differs from the golden vector"
    chk = verify_response(res, kd, art)
    assert chk["ok"], (name, chk)
    ok += 1
    print(f"{name:32} {got['final_epistemic_state']:26} {got['status']:9} receipt ok")
# tampering is detected
res2 = copy.deepcopy(res); res2["result"]["decision"]["final_epistemic_state"] = "Verified Fact"
assert not verify_response(res2, kd)["ok"]
exp = gv.export()
assert verify_export(exp, kd)["ok"], verify_export(exp, kd)
bad = copy.deepcopy(exp); del bad["entries"][1]
assert not verify_export(bad, kd)["ok"]
print("export:", verify_export(exp, kd)["entries"], "entries, chain ok; deleting one entry is detected")
print("history:", [d["decision_id"] for d in gv.decisions(limit=3)])
print("usage:", gv.usage())
for bad_body, expect in [({"artifact": {"evidence": []}}, 422)]:
    try:
        gv._call("POST", "/verify", bad_body); raise SystemExit("expected an error")
    except ApiError as e:
        assert e.status == expect, e
try:
    Client("gv_" + "0" * 48, base).usage(); raise SystemExit("expected 401")
except ApiError as e:
    assert e.status == 401
print(f"ALL OK ({ok} decisions match the golden vectors)")
