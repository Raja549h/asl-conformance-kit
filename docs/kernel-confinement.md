# Kernel-Level Egress Confinement — PROVEN under WSL2

This records the one claim the project could not previously make on its primary
host: that a confined child has **no IP route at all**, not merely no *unwired*
one. That claim is now backed by three passing tests on a Linux host, and the
signed evidence report reflects it.

## The claim

A child process placed in a fresh Linux network namespace cannot reach even a
fake server bound to `127.0.0.1`, while the **mediated channel** — an `AF_UNIX`
socket, which the namespace does not partition — keeps working. That is the
strongest form of the section-A claim: the only door out is the mediated one,
and the kernel, not the code, closes the others.

## The host

| Property | Value |
|---|---|
| Distribution | Ubuntu 26.04.1 LTS (WSL2) |
| Kernel | `6.18.54.1-microsoft-standard-WSL2` |
| WSL version | `3.0.3.0` (default version 2) |
| Python (venv) | 3.14.4 |
| bubblewrap | 0.11.1 |
| Capabilities detected | `network_namespace=True`, `bubblewrap=True`, `resource_limits=True`, `can_deny_egress=True` |

Measured by `asl level` on this host:

```
Capabilities: platform=linux, resource_limits=True, network_namespace=True,
              bubblewrap=True, job_objects=False
```

## The three tests

`tests/test_egress_kernel.py` — **3 passed**:

| Test | What it proves |
|---|---|
| `TestNetworkNamespaceHasNoDirectRoute::test_a_namespaced_child_cannot_reach_a_fake_loopback_server` | A child under `unshare --net` gets `NO_ROUTE` against a live loopback server, and the server records **zero** requests. The child has no route, not merely a disallowed one. |
| `TestNetworkNamespaceHasNoDirectRoute::test_a_namespaced_child_can_still_use_the_mediated_channel` | The same namespaced child **can** still reach the outside — but only through the `AF_UNIX` mediated channel, with a valid single-use, request-bound capability token, and it gets a real `200` back. |
| `TestBubblewrapHasNoDirectRoute::test_a_bubblewrapped_child_cannot_reach_a_fake_loopback_server` | The same no-route property holds under `bwrap --unshare-all --dev-bind / /`, the second (independent) confinement mechanism. |

## Reproducing

From an elevated prompt, once:

```powershell
wsl --install -d Ubuntu --no-launch
wsl -d Ubuntu -u root -- bash -c "apt-get update && apt-get install -y bubblewrap python3-venv python3-pip"
```

Then, from the repository:

```powershell
wsl -d Ubuntu -- bash -c "cd /mnt/c/asl && python3 -m venv .venv-linux && .venv-linux/bin/pip install -e '.[dev,vault]' && .venv-linux/bin/pytest tests/test_egress_kernel.py -q"
wsl -d Ubuntu -- bash -c "cd /mnt/c/asl && .venv-linux/bin/python -m asl.cli level"
```

The verifier prints `3 passed`; the level command prints:

```
ASL containment level: L4.5 (Full Kernel + Mediated)
  - L4.5 achieved with kernel namespace confinement
  ...
  [x] kernel namespace confinement detected
```

`.venv-linux` is a local Linux-only test environment and is gitignored.

## A probe defect this run exposed

`require_bubblewrap()` originally probed `bwrap --unshare-all -- true`. That is
**not** how the test invokes bubblewrap: with no root bind the new mount
namespace is empty, so bwrap cannot even `execvp true` and the probe reports
bubblewrap as unavailable on a host where it plainly works. The probe now runs
the same flag set the test uses, `bwrap --unshare-all --dev-bind / / -- true`,
so the skip reason (if one ever appears) names a real host limitation.

## What is still not claimed

* **Native Windows remains UNPROVEN.** This host has no Linux namespaces, so the
  same tests skip there with an explicit reason and the Windows report says
  `can_deny_egress: False`. The Windows-host report is kept verbatim beside the
  Linux one as `docs/signed-evidence-report-windows.json` / `.md`.
* **The mediated half across the boundary is proven; the product's tool-call
  path is still not fully wired** (`docs/limits.md` items 14, 20, and the rest).
* Everything still listed as UNTESTED in [limits.md](limits.md) and the honest
  gaps in [invariants.md](invariants.md) — real-model agents and swarms, the
  hardware kill actuator and heartbeat sink, eBPF telemetry, and the
  off-box witness shorthand — is unaffected by this result.

## The report now on disk

`docs/signed-evidence-report.json` (and `.md`) is the **Linux-host** report:
level **L4.5 (Full Kernel + Mediated)**, `platform: linux`, signed HMAC-SHA256.
The previous Windows-host report — level **L4.5 (Architecture Verified)**,
`platform: win32` — is preserved unchanged as
`docs/signed-evidence-report-windows.json` (and `.md`).
