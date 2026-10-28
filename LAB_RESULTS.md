# Lab method and results

## Title

**Offline simulation of ARP cache poisoning, clear-text exposure and layered defenses**  
Course: Secure Networks (23CSE336)  
Related case: ARP cache poisoning and MITM on a corporate finance LAN

## Objective

Model the security outcome of five conditions relevant to the provided case study: normal operation, an ARP-based interception attempt against HTTP, the same redirection against correctly validated TLS, Dynamic ARP Inspection (DAI) backed by DHCP snooping, and a layered DAI/TLS/HSTS posture. The model makes the Layer 2 redirect and the application-layer confidentiality control separable so the result demonstrates which control addresses which risk.

## Hypothesis

If false gateway ARP mappings are accepted, a host’s Ethernet frames can be redirected to the attacker while the IP endpoints remain unchanged. If the intercepted application traffic is clear text, synthetic credentials can be observed. If TLS is correctly validated, the network redirect can still occur, but the application payload should remain unreadable and tampering should fail at the authenticated transport. If DAI rejects the false mapping against a correct binding, host redirection should not occur.

## Method

`run_lab.py` is a deterministic, offline state model. It represents eight synthetic finance endpoints (192.168.40.51–58), a gateway, an attacker MAC, and three synthetic sensitive flows per endpoint per condition. It models two false gateway claims per endpoint to represent both traffic directions. In the DAI conditions, all 16 claims are rejected. In unprotected MITM conditions, the model accepts claims and marks each host redirected. HTTP exposes the synthetic flows; validated TLS protects application payloads while permitting observation of connection metadata and leaving availability disruption possible. The downgrade example models one legacy client that allows HTTP fallback and one client with an active HSTS policy.

No raw packet is generated or transmitted. There are no sockets, packet-capture adapters, real devices, real passwords or real user data. The model does not emulate an OS neighbor cache, a specific switch implementation, TLS cryptography, a real mobile app or measured network latency. It encodes the stated assumptions to make the control comparison reproducible and understandable.

## Results

| Condition | Synthetic sensitive flows generated | False claims accepted | Hosts redirected | Clear-text flows visible | Synthetic login credentials exposed | False claims DAI dropped |
|---|---:|---:|---:|---:|---:|---:|
| Baseline / no attacker | 24 | 0 | 0 | 0 | 0 | 0 |
| ARP MITM / HTTP | 24 | 16 | 8 | 24 | 8 | 0 |
| ARP MITM / TLS validated | 24 | 16 | 8 | 0 | 0 | 0 |
| DAI + snooping / HTTP | 24 | 0 | 0 | 0 | 0 | 16 |
| Layered: DAI + TLS + HSTS | 24 | 0 | 0 | 0 | 0 | 16 |

In the HTTP scenario, one of the three flows per redirected host is a credential-bearing login flow; the other two are illustrative payment-related flows. Accordingly, the model counts eight exposed synthetic login credentials and 24 visible HTTP flows. These counts describe the simulation configuration only and must not be attributed to the source case.

## Interpretation

1. **ARP affects link-layer delivery.** The frame’s destination MAC changes to the attacker’s address, while the workstation/gateway IP endpoints remain the same.
2. **Encryption changes the impact after redirection.** With correctly validated TLS, the model still shows eight redirected hosts, but zero clear-text application flows or credentials exposed. Metadata and denial-of-service risk remain.
3. **DAI prevents the modeled cache change.** Where the switch validates claims against correct DHCP snooping bindings, all 16 synthetic false claims are dropped, leaving zero modeled redirected hosts.
4. **Defense in depth is stronger than either control alone.** DAI prevents the described local poisoning path; TLS protects application confidentiality and integrity if the Layer 2 prevention fails or another network path is hostile; HSTS removes a downgrade route for a policy-aware client.
5. **The controls have assumptions.** DAI depends on accurate bindings and explicit handling for static IPs and legitimate gateway redundancy. TLS protection depends on strict client certificate and hostname validation. HSTS requires a conforming client and a secure way to learn policy (or preload).

## SSL downgrade example

The separate `ssl_downgrade_examples.csv` contains two simplified client profiles. The legacy profile permits the downgrade path in the model. The browser profile with a known/preloaded HSTS policy refuses HTTP. This is a conceptual comparison, not execution of a real SSL-stripping tool or mobile application.

## Evidence files and screenshot captions

- **Figure 1 — Main simulation dashboard:** `results/01_simulation_results.png`. Shows modeled host redirection and synthetic credential exposure across conditions, with the simulation-only label.
- **Figure 2 — Frame-level change:** `results/02_frame_change.png`. Compares normal and poisoned Ethernet destination MACs and unchanged IP endpoints.
- **Figure 3 — Control comparison:** `results/03_defense_comparison.png`. Summarizes redirection, exposure, DAI drops and tampering possibility.
- **Figure 4 — Command-line result rendering:** `results/04_terminal_results.png`. Cleanly formats the script’s result counts; it is a generated presentation rendering, not a screenshot of a live terminal window.
- `results/scenario_results.csv`: machine-readable aggregate outcomes.
- `results/event_log.csv`: sorted synthetic events with UTC timestamps and scenario labels.
- `results/run_metadata.json`: model parameters, safety notes and generation time.

## Limitations

The output is not an empirical reproduction, penetration test, packet capture, proof of breach, or performance benchmark. Counts are directly determined by the chosen model parameters. A real environment may behave differently because ARP cache handling varies, switch trust boundaries and DAI implementations vary, static bindings may be used, some clients reject unsolicited ARP, and application/session behavior differs. The supplied course case remains the source for the Ashwin Holdings narrative; these results are a companion teaching demonstration.

## Conclusion

The simulation supports the case study’s main technical lesson: a local ARP redirection can position an attacker in the traffic path, but clear-text application design is what makes credentials trivially observable. DAI backed by trustworthy bindings blocks the modeled false mapping, while validated TLS limits the consequences if redirection occurs. A real-world case conclusion would require authorized packet and system evidence; this offline model provides reproducible teaching outputs without claiming to recreate a live event.

## References

- RFC 826, Address Resolution Protocol: https://www.rfc-editor.org/rfc/rfc826.html
- RFC 5227, IPv4 Address Conflict Detection: https://www.rfc-editor.org/rfc/rfc5227.html
- RFC 8446, TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 9525, Service Identity in TLS: https://www.rfc-editor.org/rfc/rfc9525.html
- RFC 6797, HTTP Strict Transport Security: https://www.rfc-editor.org/rfc/rfc6797.html

- **Figure 5 — Host-by-scenario heatmap:** `results/05_host_scenario_heatmap.png`. Each synthetic endpoint is shown for each modeled condition. All hosts share the same outcome by design.
- **Figure 6 — Control-outcome heatmap:** `results/06_control_outcome_heatmap.png`. Compares host redirection, credential exposure, DAI drops, metadata visibility, payload tampering and denial-of-service possibility. Count scales are normalized within each column; DAI drops use teal to distinguish protective enforcement from exposure.
