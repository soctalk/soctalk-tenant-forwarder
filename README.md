# soctalk-tenant-forwarder

> **Status: deprecated / reference-only.** Superseded by
> [`soctalk-adapter`](https://github.com/soctalk/soctalk) (built from
> `src/soctalk_adapter/` in the main repo). This repo is kept read-only
> as a minimal reference implementation; it is **not deployed** by any
> SocTalk chart and receives no further development.

A ~180-line L2→L1 alert forwarder: it polls a tenant's local Wazuh
indexer for new alerts, maps each to the `AdapterEvent` shape the L1
ingest endpoint expects, and POSTs batches with a mounted adapter JWT.

It was the thinnest workable stand-in for the per-tenant adapter during
early MVP bring-up. The production component that replaced it,
`soctalk-adapter`, adds everything this forwarder omits:

| Capability | `soctalk-adapter` | this forwarder |
|---|---|---|
| Alert ingest (Wazuh → L1) | yes | yes |
| Heartbeat to L1 (`/api/internal/adapter/heartbeat`) | yes | **no** |
| Health / status endpoint | yes (FastAPI) | no |
| Cursor | persistent, supports backfill | in-memory, resumes from "now" |
| Per-tenant rate limiting | yes | no |
| Config refresh | yes | no |

The missing **heartbeat** is load-bearing: it is the signal L1 uses to
know a tenant's data plane is alive. A tenant running only this
forwarder would appear dead to L1.

## If you need a forwarder

Use `soctalk-adapter`. The `soctalk-tenant` Helm chart deploys it
automatically during tenant provisioning
(`charts/soctalk-tenant/values.yaml` → `adapter.image.repository`).

## Image

The container image remains published for historical reference:
`ghcr.io/soctalk/soctalk-tenant-forwarder` (`latest`, `0.1.1`). No Helm
chart is published — this component is not standalone-deployed.
