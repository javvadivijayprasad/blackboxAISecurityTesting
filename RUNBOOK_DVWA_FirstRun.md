# Runbook — first live DVWA run (Paper K oracle)

Goal: take the oracle from "unit tests pass" to "one real, graded run against DVWA," so the
pipeline is proven on a real target before any expensive multi-provider batch. Everything
here runs on your PC (Windows + Docker Desktop). Paths assume the repo at
`E:\EB1A_Research\EB1_Master\06_Authorship\Paper_K_PHPSecurity_ExploitValidation\Experiment\oracle`.

Work in this order — each step gates the next.

## 0. Prerequisites (once)
- Docker Desktop running (`docker version` returns client+server).
- Python 3.11+ (`python --version`).
- From the oracle folder:
  ```
  cd E:\EB1A_Research\EB1_Master\06_Authorship\Paper_K_PHPSecurity_ExploitValidation\Experiment\oracle
  pip install -r requirements.txt
  set PYTHONPATH=.
  python -m pytest -q
  ```
  Expect `8 passed`. If not, stop — the core is broken and nothing downstream is trustworthy.

## 1. Stand up DVWA (pinned build)
DVWA is already cloned at `..\targets\DVWA` (commit a1978a2). Bring it up:
```
cd ..\targets\DVWA
docker compose up -d --build
```
- Open `http://localhost:4280` (check the compose file for the published port; adjust if different).
- Log in `admin` / `password`.
- Click **Create / Reset Database** (setup.php), then log in again.
- Record the running container name: `docker ps` → note it (e.g. `dvwa-dvwa-1`). You need it for PlantConfig.
- Record the image digest for the manifest:
  ```
  docker image inspect --format "{{index .RepoDigests 0}}" <dvwa-image>
  ```

### Security levels as separate runs (important — see design s6)
Do NOT test "low" and "impossible" in one run. The oracle measures false positives only when
the tool is pointed at a build with no vulnerable instance. So:
- **Run A:** DVWA security = **low** (the vulnerable build). Positives live here.
- **Run B:** DVWA security = **impossible** (the control build). Any flag here is a false positive.
The security level is set per session via the DVWA Security page / cookie. For a clean separation,
run A fully, reset, set impossible, run B. Keep them as two RunResults with the same target key but
different `run_id` suffixes (`DVWA-low-...`, `DVWA-impossible-...`).

## 2. Fill the DVWA PlantConfig
Edit a small per-target config (e.g. `targets_config.py` you create next to the package, or inline
in your run script). Minimum for the four example classes:
```python
from paperk_oracle.planter import PlantConfig
DVWA = PlantConfig(
    container="dvwa-dvwa-1",                    # from docker ps
    canary_path="/var/www/html/oracle_canary.txt",   # for lfi.canary
    sentinel_path="/tmp/aqa_{nonce}",                 # for rce.sentinel_file
    db_exec=["mysql","-uroot","-pp@ssw0rd","dvwa","-e"],  # confirm creds from the compose file
    admin_resource_hint="",                     # not needed for the 4 example classes yet
)
```
Then make the SQLi secret table exist after reset (one-time per container), either in the planter
or a small setup step:
```
docker exec dvwa-dvwa-1 mysql -uroot -p<pw> dvwa -e "CREATE TABLE IF NOT EXISTS oracle_secret (token VARCHAR(64));"
```

## 3. Author the full DVWA label set
The example file `labels/DVWA.labels.example.yaml` has 6 entries. For the first run, extend it to the
classes you want measured (command injection, file inclusion, file upload, SQLi to start). Rules:
- One label per (class, security level) you test; low = `is_vulnerable: true`, impossible = `is_vulnerable: false`.
- Fill `endpoint_family` consistently (exec / fi / upload / sqli) — the matching rubric keys on it.
- Keep `oracle_check` matching the planter: `rce.sentinel_file`, `lfi.canary`, `sqli.secret_row`.
- Validate before running:
  ```
  set PYTHONPATH=.
  python -m paperk_oracle.cli validate labels\
  ```

## 4. Wire one scanner baseline (ZAP) — the cheap control first
Before spending agent tokens, prove the pipeline with a free tool.
- Start ZAP in daemon mode (ZAP Docker image or local install), note its API addr + key.
- Implement the TODO in `paperk_oracle/adapters/zap.py`: spider + active scan `base_url`, map each
  alert to a `Finding(reported_class=alert name, method, path, param, evidence)`.
- ZAP won't surface the planted nonce, so its exploit-success should come out ~0 — that's expected and
  is itself the contrast the paper reports. If ZAP shows exploit>0, the oracle is leaking the nonce —
  investigate before trusting anything.

## 5. Wire the attestqa adapter
Implement the TODO in `paperk_oracle/adapters/attestqa.py`:
- Input the agent gets: `base_url`, low-priv creds, and `callback_url` (from the interaction server) to
  use in payloads. Nothing else — no labels, no nonces, no canary paths.
- Output: structured `Finding`s + the full transcript + token/USD/time usage.
- Provider is set via env so the same adapter runs on Claude / OpenAI / Gemini (RQ4).

## 6. First graded run (ZAP, security=low)
Write a short `run_dvwa.py`:
```python
import os; os.environ.setdefault("PYTHONPATH",".")
from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores
from paperk_oracle.adapters.zap import ZapAdapter
from targets_config import DVWA

labels = load("labels/DVWA.labels.example.yaml")
spec = TargetSpec(key="DVWA", base_url="http://localhost:4280",
                  compose_dir=r"..\targets\DVWA", plant_cfg=DVWA,
                  creds={"user":"admin","pass":"password"})
score = run_once(ZapAdapter(), spec, labels, run_id="DVWA-low-zap-r0", use_docker=True)
save_scores([score], "scores.DVWA.zap.json")
```
Run it, then:
```
python -m paperk_oracle.cli report scores.DVWA.zap.json
```
Sanity checks: detections land on the right classes; exploit-success ~0 for ZAP; no crash on reset/plant.

## 7. First agent run (attestqa, security=low), then the control
Swap `ZapAdapter()` for `AttestqaAdapter(provider="claude", callback_url=...)`. Start small — one provider,
one run. Confirm: at least one class confirmed via nonce (exploit=true), cost recorded. Then repeat the
whole thing with DVWA at **impossible** (`run_id="DVWA-impossible-..."`) to get the false-positive side.

## 8. Scale out (only after 6–7 are clean)
- N = 3–5 repeats per (tool, target, level): `run_repeats(...)`.
- Add OpenAI and Gemini providers.
- Add the other targets (Mutillidae, WackoPicko, vulhub-selected) once DVWA is solid.
- Keep every `scores.*.json`; `metrics.per_class` + `pass_at_k` + `cost_summary` across them produce the
  paper's tables. Report mean±stdev across runs; significance-test any headline difference.

## 9. Cost discipline
Agent runs bill your Console org ($200/mo Max credits). Measure cost on the first DVWA agent run, then
extrapolate before the full batch (≈ targets × providers × repeats). Cost is a reported result, not just
a budget line — the oracle already records tokens/USD/time per run.

## Guardrails
- Targets are deliberately vulnerable: keep them bound to localhost, never expose the ports.
- The interaction server is localhost-only; fine for the planted-payload cases. Add DNS only if a target needs it.
- If `git`/Docker leaves lock files in the connected folder, that's the delete-permission limitation — it
  doesn't affect Docker runs, only git operations inside the folder.

## Definition of done for "first run"
One `scores.DVWA.*.json` each for attestqa at low and at impossible, a clean `report` for both, at least one
nonce-confirmed exploit, and recorded cost. At that point the pipeline is proven and the rest is scale.
