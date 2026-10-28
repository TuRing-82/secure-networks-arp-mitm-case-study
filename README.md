# Secure Networks case study lab package

## What this is

A reproducible **offline simulation** to accompany the ARP cache-poisoning / man-in-the-middle case study for Secure Networks (23CSE336). It demonstrates how a forged gateway mapping can redirect frames, why clear-text HTTP exposes synthetic data, why validated TLS protects the payload, and how DHCP snooping plus Dynamic ARP Inspection (DAI) can reject forged claims when bindings are correct.

**Safety and evidence label:** the script uses a deterministic synthetic model. It opens no network sockets, does not use Scapy, does not send ARP packets, and does not collect real credentials. The counts are model outputs, not measurements from Ashwin Holdings, a campus LAN, or any production network. Present these as *simulation results*, not as proof that the case incident was reproduced on live equipment.

## Run it

1. Install Python 3.10 or later.
2. Open PowerShell in this folder.
3. Optional: create a virtual environment with `python -m venv .venv` and activate it.
4. Install the image dependency: `python -m pip install -r requirements.txt`.
5. Run `python run_lab.py`.
6. Open the `results` folder. Each run overwrites the generated CSV, JSON and PNG outputs deterministically (model ID 336); the `run_utc` field in JSON records when that output set was generated.

No administrator privileges or network connection are needed.

## Scenarios modeled

| Condition | Expected result in the model |
|---|---|
| Baseline, no attacker | No forged claims and no redirection |
| ARP MITM, HTTP | Eight synthetic endpoints redirected; one synthetic login secret per redirected host exposed |
| ARP MITM, validated TLS | Frames redirect, but application payload remains encrypted; metadata and denial-of-service risk remain |
| DAI + DHCP snooping, HTTP | Forged claims are rejected; no victim mapping changes |
| Layered DAI + TLS + HSTS | Mapping is rejected and the transport downgrade example is blocked for the policy-aware client |

The model generates 24 synthetic sensitive flows per condition (8 hosts × 3 flows). Only redirected flows can be observed by the simulated on-path attacker. The HTTP case models one credential-bearing login flow per affected host; the other synthetic flows represent payment-related traffic. No actual usernames or passwords are present.

## Files

- `run_lab.py` — complete simulation and image-generation source.
- `results/scenario_results.csv` — one row per condition, with redirect, exposure, DAI and tampering measures.
- `results/event_log.csv` — synthetic event sequence for ARP claims, DAI drops and intercepted flows.
- `results/ssl_downgrade_examples.csv` — simplified comparison of a legacy client and a policy-aware browser.
- `results/run_metadata.json` — seed, parameters, safety statement and output inventory.
- `results/01_simulation_results.png` — dashboard-style screenshot of the main result.
- `results/02_frame_change.png` — frame-level comparison showing the Ethernet destination change and unchanged IP endpoints.
- `results/03_defense_comparison.png` — comparative outcomes across control conditions.
- `results/04_terminal_results.png` — screenshot-style rendering of the command-line summary.
- `LAB_RESULTS.md` — ready-to-use methodology, results, interpretation and limitations.

## Suggested screenshots for your submission

Use `01_simulation_results.png` as the main results screenshot and `02_frame_change.png` to explain the packet mechanics. `03_defense_comparison.png` supports the countermeasure discussion. If your instructor expects evidence of execution, capture your own terminal after running `python run_lab.py`; the generated `04_terminal_results.png` is a clean presentation rendering, while a live terminal screenshot records your local run.

## Protocol references

- RFC 826, Address Resolution Protocol: https://www.rfc-editor.org/rfc/rfc826.html
- RFC 5227, IPv4 Address Conflict Detection: https://www.rfc-editor.org/rfc/rfc5227.html
- RFC 8446, TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 9525, Service Identity in TLS: https://www.rfc-editor.org/rfc/rfc9525.html
- RFC 6797, HTTP Strict Transport Security: https://www.rfc-editor.org/rfc/rfc6797.html
- Cisco Dynamic ARP Inspection guidance: https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/fhs-sisf/fhs-and-sisf-configuration-guide/dynamic-arp-inspection.html


## Heatmaps added

- `results/05_host_scenario_heatmap.png` shows the modeled state of each synthetic host under all five conditions: normal, clear-text exposed, redirected but protected by TLS, or protected by DAI.
- `results/06_control_outcome_heatmap.png` compares redirection, credential exposure, DAI drops, metadata visibility, payload tampering and denial-of-service possibility. Red indicates modeled exposure; teal indicates DAI enforcement activity.

Both visuals display simulated outcomes, not observations from real endpoints.
