# PENT-15 — Two-Stage "Clean Dropper" Lab (`dropper_lab`)

This directory contains the isolated, loopback-only study fixtures for **PENT-15 (Two-Stage "Clean Dropper" Detection Harness)**, modeling the two-stage trojan/dropper architecture covered in the `MYO062` lecture (19.10: *"yeni nesil Truva atı: tertemiz gelir, zararlı sonradan buluttan iner"*).

## Safety & Lab Scope Guarantees

1. **Loopback-Only Networking (`127.0.0.1`):** Both `stage2_server.py` and `stage1_clean_loader.py` enforce `assert_loopback_host()` / `assert_loopback_url()` and immediately raise `ValueError` if any non-loopback address is supplied.
2. **Inert Educational Payload:** The stage-2 payload sets a harmless string constant (`STAGE2_MARKER = 'OSLAB_BENIGN_STAGE2_MARKER_v1'`) inside an isolated dictionary with empty `__builtins__`.
3. **Negative Control Included:** `benign_utility.py` is a clean utility module used to verify zero false positives in `dropper_detect.py`.

## Contents

| File | Purpose |
| --- | --- |
| `stage2_server.py` | Local `127.0.0.1` HTTP server serving `/stage2.json` and `/stage2.js`, plus one-shot `--rehearse` runner |
| `stage1_clean_loader.py` | Python stage-1 loader modeling deferred timer + loopback HTTP fetch + base64 decode + `compile`/`exec` |
| `stage1_extension_loader.js` | Browser-extension stage-1 loader modeling `setTimeout` + `fetch` + `atob` + `new Function`/`eval` |
| `benign_utility.py` | Clean local helper script (negative control; scores `0 / CLEAN`) |

## Quick Start

```bash
# Run the detector against the entire lab directory (JSON or Markdown)
python3 scripts/analysis/dropper_detect.py scripts/analysis/dropper_lab --markdown

# Run a live loopback rehearsal (starts 127.0.0.1 stage-2 server on an ephemeral port, runs stage-1, and audits both)
python3 scripts/analysis/dropper_detect.py scripts/analysis/dropper_lab --rehearse
```
