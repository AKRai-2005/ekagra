"""Read-only HTTP surface for the enclave console.

The constraint this file has to satisfy
----------------------------------------
`tests/test_readonly_constraint.py` exempts `api/` from the no-sockets rule,
because serving results to an analyst is not a path back into the monitored
network. That exemption is only honest if the API genuinely cannot become one,
so three properties are enforced rather than assumed:

1. **The API never touches the detection path.** It does not import `ingest`,
   does not hold a packet source, and does not run a sensor. It reads a
   finished evidence log from disk. A process that has no handle on ingest
   cannot influence what is ingested, whatever an attacker does to its HTTP
   surface.

2. **Every route is GET.** There is no endpoint that writes, re-runs, re-scores
   or re-configures anything. `test_api.py` asserts this over the route table,
   so adding a POST later fails the build rather than quietly widening the
   surface.

3. **Bind address is explicit and defaults to loopback.** An enclave console
   that binds 0.0.0.0 by default is a mistake waiting for a deployment, so
   `serve()` requires the operator to say otherwise.

What it deliberately does not do
---------------------------------
No authentication, no TLS, no rate limiting. Those belong to the enclave's own
perimeter, and a hand-rolled auth layer here would be worse than none - it
would imply a guarantee this does not provide. Stated rather than omitted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from ..detect.heads import ALL_HEADS
from ..evidence.bundle import EvidenceLog

DEFAULT_LOG = Path(__file__).resolve().parents[3] / "results" / "exp08_evidence.jsonl"
# The console now lives in a sibling `frontend/` folder so it can be worked on
# independently of the Python. parents[3] is the backend root; its parent is the
# project root.
CONSOLE_DIR = Path(__file__).resolve().parents[3].parent / "frontend"
RESULTS_DIR = Path(__file__).resolve().parents[3] / "results"


class AlertStore:
    """Loads a finished evidence log and answers queries about it.

    Deliberately a plain object rather than a database: the log is append-only,
    written by a separate process, and read whole. Anything more would imply
    the API can change it.
    """

    def __init__(self, log_path: Path = DEFAULT_LOG, key: bytes = b"") -> None:
        self.log_path = Path(log_path)
        self.key = key
        self.log: Optional[EvidenceLog] = None
        self._verify_cache: Optional[List[str]] = None

    def load(self) -> "AlertStore":
        if not self.log_path.exists():
            raise FileNotFoundError(
                f"{self.log_path} not found - run "
                f"experiments/exp08_evidence_console.py first")
        self.log = EvidenceLog.read_jsonl(self.log_path, key=self.key)
        self._verify_cache = None
        return self

    @property
    def bundles(self):
        if self.log is None:
            self.load()
        return self.log.bundles

    def verify(self) -> List[str]:
        if self._verify_cache is None:
            if self.log is None:
                self.load()
            self._verify_cache = self.log.verify()
        return self._verify_cache


def create_app(log_path: Path = DEFAULT_LOG, key: bytes = b"",
               console_dir: Path = CONSOLE_DIR) -> FastAPI:
    app = FastAPI(title="EKAGRA enclave console",
                  description="Read-only view over a signed alert log.",
                  version="0.1.0", docs_url="/api/docs")
    store = AlertStore(log_path, key)

    @app.get("/api/health")
    def health() -> Dict:
        try:
            n = len(store.bundles)
            return {"status": "ok", "entries": n, "log": str(store.log_path)}
        except FileNotFoundError as e:
            # A missing log is an operational state, not a server fault: the
            # sensor may simply not have run yet.
            return {"status": "no-log", "detail": str(e)}

    @app.get("/api/summary")
    def summary() -> Dict:
        b = store.bundles
        problems = store.verify()
        s = store.log.summary()
        return {
            **s,
            "chain_verified": not problems,
            "chain_problems": problems[:10],
            "first_window": b[0].window if b else None,
            "last_window": b[-1].window if b else None,
        }

    @app.get("/api/heads")
    def heads() -> List[Dict]:
        """The head roster, with each head's stated mechanism.

        Serving the rationale next to the alerts is the point: an analyst
        seeing "beacon fired" can read what the beacon head actually keys on
        without opening the source.
        """
        return [{
            "name": h.name,
            "threat_class": h.threat_class,
            "rationale": h.RATIONALE,
            "declared_features": list(h.FEATURES),
            "known_gap": h.HANDICAPPED,
        } for h in ALL_HEADS]

    @app.get("/api/alerts")
    def alerts(limit: int = Query(100, ge=1, le=1000),
               offset: int = Query(0, ge=0),
               threat_class: Optional[str] = None,
               decision: Optional[str] = None) -> Dict:
        rows = store.bundles
        if threat_class:
            rows = [b for b in rows if b.threat_class == threat_class]
        if decision:
            rows = [b for b in rows if b.decision == decision.upper()]
        page = rows[offset:offset + limit]
        return {
            "total": len(rows), "offset": offset, "limit": limit,
            "alerts": [{k: v for k, v in b.to_dict().items()
                        if k not in ("features",)} for b in page],
        }

    @app.get("/api/alerts/{seq}")
    def alert(seq: int) -> Dict:
        for b in store.bundles:
            if b.seq == seq:
                return b.to_dict()
        raise HTTPException(status_code=404, detail=f"no alert with seq {seq}")

    @app.get("/api/verify")
    def verify() -> Dict:
        problems = store.verify()
        return {"verified": not problems, "problems": problems,
                "entries": len(store.bundles),
                "head": store.log.head if store.bundles else None}

    @app.get("/events")
    def events(start: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=5000)):
        """Replay alerts as Server-Sent Events, in log order.

        A replay rather than a live tail: the sensor writes the log in a
        separate process and this is a read-only view of it. Presenting a
        replay as a live feed would misrepresent where the data comes from.
        """
        def gen():
            for b in store.bundles[start:start + limit]:
                payload = {k: v for k, v in b.to_dict().items()
                           if k not in ("features",)}
                yield f"event: alert\ndata: {json.dumps(payload)}\n\n"
            yield "event: end\ndata: {}\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/figures")
    def figures() -> List[Dict]:
        """The evidence figures, with the claim each one carries.

        The manifest is written by `make_figures_pipeline.py` alongside the
        images, so a figure and its caption cannot drift apart - the alternative
        was a second copy of the captions here, which would go stale the first
        time an experiment was re-run.
        """
        man = RESULTS_DIR / "figures.json"
        if not man.exists():
            return []
        return [r for r in json.loads(man.read_text())
                if (RESULTS_DIR / r["file"]).exists()]

    @app.get("/figures/{name}")
    def figure(name: str):
        """Serve one figure.

        Only names the manifest declares are served. `name` reaches the
        filesystem, so an allowlist is the guard - not a prefix check, which
        `..%2f` walks straight through.
        """
        man = RESULTS_DIR / "figures.json"
        allowed = {r["file"] for r in json.loads(man.read_text())} if man.exists() else set()
        if name not in allowed:
            raise HTTPException(status_code=404, detail=f"no figure {name!r}")
        path = RESULTS_DIR / name
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"{name} not generated yet")
        return FileResponse(path, media_type="image/png")

    @app.get("/", response_class=HTMLResponse)
    def console():
        index = Path(console_dir) / "index.html"
        if not index.exists():
            return HTMLResponse("<h1>frontend/index.html not found</h1>", status_code=404)
        return FileResponse(index)

    @app.get("/data.js")
    def console_data():
        f = Path(console_dir) / "data.js"
        if not f.exists():
            raise HTTPException(status_code=404, detail="data.js not generated yet")
        return FileResponse(f, media_type="application/javascript")

    app.state.store = store
    return app


def serve(host: str = "127.0.0.1", port: int = 8000,
          log_path: Path = DEFAULT_LOG, key: bytes = b"") -> None:
    """Run the console server.

    Defaults to loopback on purpose. Binding 0.0.0.0 in an enclave should be a
    decision someone typed, not a default they inherited.
    """
    import uvicorn
    uvicorn.run(create_app(log_path, key), host=host, port=port, log_level="info")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", default=str(DEFAULT_LOG))
    args = ap.parse_args()
    serve(args.host, args.port, Path(args.log))
