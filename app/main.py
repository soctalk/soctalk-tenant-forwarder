"""soctalk-tenant-forwarder — minimal L2→L1 alert forwarder.

Polls the local Wazuh indexer for new alerts, maps each to the
``AdapterEvent`` shape the L1 MSSP SocTalk ingest endpoint expects
(soctalk/core/api/adapter.py), and POSTs batches to the L1 URL with
a mounted adapter JWT.

This is the thinnest workable stand-in for the full soctalk-adapter
service: no case hydration, no config refresh, just forward-and-ack.
Cursor is a timestamp kept in-memory — on pod restart we resume from
"now", skipping whatever backlog accumulated. Good enough for the MVP
harness; a persistent cursor + replay is follow-up work.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


# ----------------------------------------------------------------------
# Config (env-only; the tenant chart renders these through values).
# ----------------------------------------------------------------------


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"{name} env var required")
    return v


def _load_adapter_token() -> str:
    path = Path(os.environ.get("ADAPTER_TOKEN_PATH", "/run/secrets/adapter/token"))
    if not path.is_file():
        raise RuntimeError(f"adapter token not mounted at {path}")
    return path.read_text().strip()


INDEXER_URL = _require("WAZUH_INDEXER_URL")          # https://release-wazuh-indexer.ns.svc:9200
INDEXER_USER = _require("WAZUH_INDEXER_USER")
INDEXER_PASS = _require("WAZUH_INDEXER_PASSWORD")
L1_URL = _require("SOCTALK_L1_URL").rstrip("/")      # https://l1.mssp.example
TENANT_ID = _require("SOCTALK_TENANT_ID")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "10"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
INDEX_PATTERN = os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("forwarder")


# ----------------------------------------------------------------------
# Mapping: Wazuh alert → AdapterEvent
# ----------------------------------------------------------------------


def _map_alert(hit: dict[str, Any]) -> dict[str, Any]:
    """Translate a Wazuh indexer ``_source`` blob into AdapterEvent.

    AdapterEvent requires: source_event_id, source, severity, asset_ids.
    Optional: rule_id, initial_iocs, ts, raw.
    """
    src = hit["_source"]
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    # Wazuh rule.level is 0-15; maps 1:1 to AdapterEvent.severity.
    severity = int(rule.get("level", 0))
    asset = agent.get("name") or agent.get("id") or "unknown"
    return {
        # _id is globally unique per document → safe as source_event_id.
        "source_event_id": hit["_id"],
        "source": "wazuh",
        "rule_id": str(rule.get("id")) if rule.get("id") else None,
        "severity": max(0, min(15, severity)),
        "asset_ids": [asset],
        "initial_iocs": [],
        "ts": src.get("@timestamp"),
        # Preserve the raw document for audit-only storage at L1.
        "raw": {"rule_description": rule.get("description")},
    }


# ----------------------------------------------------------------------
# Indexer poll + L1 push
# ----------------------------------------------------------------------


async def _fetch_new(
    indexer: httpx.AsyncClient, cursor_iso: str,
) -> tuple[list[dict[str, Any]], str]:
    """Return (hits, new_cursor_iso). Cursor is an inclusive lower bound
    on @timestamp; we advance it to the max @timestamp observed."""
    body = {
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "range": {
                "@timestamp": {"gt": cursor_iso}
            }
        },
        "_source": ["@timestamp", "rule", "agent", "data"],
    }
    r = await indexer.post(
        f"/{INDEX_PATTERN}/_search",
        json=body,
        auth=(INDEXER_USER, INDEXER_PASS),
    )
    r.raise_for_status()
    hits = (r.json().get("hits") or {}).get("hits") or []
    if not hits:
        return [], cursor_iso
    new_cursor = max(h["_source"]["@timestamp"] for h in hits)
    return hits, new_cursor


async def _push(
    client: httpx.AsyncClient, token: str, events: list[dict[str, Any]],
) -> None:
    r = await client.post(
        f"{L1_URL}/api/internal/adapter/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": TENANT_ID, "events": events},
    )
    r.raise_for_status()
    outcomes = (r.json() or {}).get("outcomes") or []
    promoted = sum(1 for o in outcomes if o.get("action") == "promoted")
    log.info(
        "pushed events=%d promoted=%d tenant=%s",
        len(events), promoted, TENANT_ID,
    )


async def main() -> int:
    token = _load_adapter_token()
    # Start "now": new deploys don't replay the backlog. Persistent
    # cursor is a follow-up; for MVP we accept that a forwarder restart
    # skips whatever alerts Wazuh indexed while we were down.
    cursor = datetime.now(timezone.utc).isoformat()
    log.info(
        "forwarder_starting tenant=%s l1=%s indexer=%s cursor=%s",
        TENANT_ID, L1_URL, INDEXER_URL, cursor,
    )

    # verify=False: Wazuh indexer in this harness uses a self-signed
    # cert generated inline by the wazuh chart's TLS bootstrap.
    async with httpx.AsyncClient(
        base_url=INDEXER_URL, verify=False, timeout=20.0,
    ) as indexer, httpx.AsyncClient(
        verify=True, timeout=20.0,
    ) as l1:
        while True:
            try:
                hits, next_cursor = await _fetch_new(indexer, cursor)
                if hits:
                    events = [_map_alert(h) for h in hits]
                    await _push(l1, token, events)
                    cursor = next_cursor
            except httpx.HTTPError as exc:
                log.warning("poll_push_failed err=%r", exc)
            except Exception as exc:  # noqa: BLE001
                log.exception("unexpected_error err=%r", exc)
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
