"""API-surface invariants.

`test_readonly_constraint.py` exempts `api/` from the no-sockets rule on the
grounds that serving results outward is not a path back into the monitored
network. That exemption is a claim, and these tests are what make it checkable:
the API must stay read-only, must never reach the detection path, and must not
bind a public interface by default.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import asyncio
from urllib.parse import urlencode

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.api.server import AlertStore, create_app, serve
from ekagra.evidence.bundle import EvidenceLog, model_digest  # noqa: E402

API_SRC = ROOT / "src" / "ekagra" / "api"


class _Response:
    __slots__ = ("status_code", "headers", "content")

    def __init__(self, status_code, headers, content):
        self.status_code = status_code
        self.headers = headers
        self.content = content

    @property
    def text(self):
        return self.content.decode("utf-8")

    def json(self):
        import json as _json
        return _json.loads(self.text)


class _AsgiClient:
    """Minimal synchronous ASGI caller.

    Not `fastapi.testclient.TestClient`: starlette 0.35 hands `app=` to
    httpx.Client, which httpx 0.28 removed, and httpx's replacement
    (`ASGITransport`) implements only the async path - so neither the old nor
    the new spelling works against the installed pair.

    Rather than pin either package for a test-only convenience, this drives the
    ASGI app directly. It covers exactly what these tests need: GET with query
    params, status, headers, and streamed bodies reassembled in order.
    """

    def __init__(self, app):
        self.app = app

    def get(self, path, params=None):
        return asyncio.run(self._call(path, params))

    async def _call(self, path, params):
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": "GET", "scheme": "http",
            "path": path, "raw_path": path.encode(), "root_path": "",
            "query_string": urlencode(params or {}).encode(),
            "headers": [(b"host", b"enclave.test")],
            "client": ("test", 1), "server": ("enclave.test", 80),
        }
        messages = []

        sent_request = False

        async def receive():
            # One request message, then suspend forever.
            #
            # Both obvious alternatives are wrong. Returning `http.request`
            # repeatedly makes starlette's disconnect-watcher spin without
            # yielding, so the response never finishes and the test hangs.
            # Returning `http.disconnect` immediately cancels a
            # StreamingResponse mid-flight and the body comes back empty.
            # Suspending lets the stream complete; the task group then cancels
            # this coroutine, which is exactly what a real client connection
            # looks like.
            nonlocal sent_request
            if not sent_request:
                sent_request = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Event().wait()

        async def send(message):
            messages.append(message)

        await self.app(scope, receive, send)

        status, headers, body = 500, {}, b""
        for m in messages:
            if m["type"] == "http.response.start":
                status = m["status"]
                headers = {k.decode().lower(): v.decode() for k, v in m["headers"]}
            elif m["type"] == "http.response.body":
                body += m.get("body", b"")
        return _Response(status, headers, body)


def TestClient(app):
    """Factory, so pytest does not try to collect the class as a test."""
    return _AsgiClient(app)


@pytest.fixture(scope="module")
def log_file(tmp_path_factory):
    """A small signed log, so the tests do not depend on exp08 having run."""
    d = tmp_path_factory.mktemp("api")
    log = EvidenceLog(key=b"k", model_hash=model_digest("m", 1))
    for i in range(25):
        log.append(alert_id=f"EK-{i:04d}", ts=100.0 + i, window=i // 5,
                   host=f"10.20.30.{10+i}",
                   threat_class=["ddos", "scan", "beacon"][i % 3],
                   score=0.6 + i / 100, confidence=0.7 + i / 200,
                   decision="ABSTAIN" if i % 7 == 0 else "ALERT",
                   features={"hw_src_n_peers": float(i),
                             "hw_dst_src_entropy": 0.5 * i},
                   observed={"flows_in_window": i, "peers": i % 4},
                   decision_path=["conformal alpha=0.10"])
    p = d / "evidence.jsonl"
    log.write_jsonl(p)
    return p


@pytest.fixture(scope="module")
def client(log_file):
    return TestClient(create_app(log_path=log_file, key=b"k"))


# ----------------------------------------------------------------- structure

def test_every_route_is_read_only(client):
    """No route may accept a method that could change anything.

    This is the test that keeps the read-only exemption honest. Adding a POST
    later fails the build rather than silently widening the surface."""
    offenders = []
    for r in client.app.routes:  # noqa: attached by the shim above
        methods = getattr(r, "methods", set()) or set()
        bad = methods - {"GET", "HEAD", "OPTIONS"}
        if bad:
            offenders.append(f"{getattr(r, 'path', r)} allows {sorted(bad)}")
    assert not offenders, "API exposes mutating routes: " + "; ".join(offenders)


def test_api_never_imports_the_ingest_path():
    """A process holding no ingest handle cannot influence what is ingested,
    whatever happens to its HTTP surface."""
    forbidden = {"ekagra.ingest", "ingest"}
    offenders = []
    for path in API_SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(node.module.endswith(f) or node.module == f for f in forbidden):
                    offenders.append(f"{path.name}:{node.lineno} {node.module}")
                # relative "from ..ingest import x"
                if node.level and node.module and node.module.split(".")[0] == "ingest":
                    offenders.append(f"{path.name}:{node.lineno} relative ingest")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[-1] == "ingest":
                        offenders.append(f"{path.name}:{node.lineno} {a.name}")
    assert not offenders, "api reaches the ingest path: " + "; ".join(offenders)


def test_serve_defaults_to_loopback():
    import inspect
    sig = inspect.signature(serve)
    assert sig.parameters["host"].default == "127.0.0.1", \
        "an enclave console must not default to a public bind address"


# ---------------------------------------------------------------- behaviour

def test_health_and_summary(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["entries"] == 25

    s = client.get("/api/summary").json()
    assert s["entries"] == 25
    assert s["chain_verified"] is True
    assert s["alerts"] + s["abstentions"] == 25


def test_alerts_paginate_and_filter(client):
    a = client.get("/api/alerts", params={"limit": 5}).json()
    assert len(a["alerts"]) == 5 and a["total"] == 25

    b = client.get("/api/alerts", params={"limit": 5, "offset": 5}).json()
    assert b["alerts"][0]["seq"] != a["alerts"][0]["seq"]

    f = client.get("/api/alerts", params={"threat_class": "scan"}).json()
    assert f["total"] > 0
    assert {x["threat_class"] for x in f["alerts"]} == {"scan"}

    d = client.get("/api/alerts", params={"decision": "abstain"}).json()
    assert {x["decision"] for x in d["alerts"]} == {"ABSTAIN"}


def test_list_view_omits_feature_vectors(client):
    """The list is a browse surface; a full feature vector per row would be
    hundreds of KB for no benefit. Detail view carries it."""
    row = client.get("/api/alerts", params={"limit": 1}).json()["alerts"][0]
    assert "features" not in row
    full = client.get(f"/api/alerts/{row['seq']}").json()
    assert full["features"], "detail view should carry the feature vector"


def test_unknown_alert_is_404(client):
    assert client.get("/api/alerts/99999").status_code == 404


def test_verify_endpoint_reports_intact(client):
    v = client.get("/api/verify").json()
    assert v["verified"] is True and v["problems"] == []
    assert len(v["head"]) == 64


def test_verify_detects_tampering(log_file, tmp_path):
    """The server must re-derive, not report a stored flag."""
    lines = log_file.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[3])
    rec["threat_class"] = "benign"
    lines[3] = json.dumps(rec, sort_keys=True)
    bad = tmp_path / "tampered.jsonl"
    bad.write_text("\n".join(lines), encoding="utf-8")

    c = TestClient(create_app(log_path=bad, key=b"k"))
    v = c.get("/api/verify").json()
    assert v["verified"] is False and v["problems"]


def test_heads_endpoint_exposes_rationale(client):
    heads = client.get("/api/heads").json()
    assert len(heads) == 6
    for h in heads:
        assert h["rationale"] and h["declared_features"]
    gaps = [h for h in heads if h["known_gap"]]
    assert len(gaps) == 2, "dga and encrypted should still declare their gap"


def test_events_stream_is_sse(client):
    r = client.get("/events", params={"limit": 3})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    body = r.text
    assert body.count("event: alert") == 3
    assert body.rstrip().endswith("data: {}")


def test_missing_log_is_an_operational_state_not_a_crash(tmp_path):
    c = TestClient(create_app(log_path=tmp_path / "nope.jsonl"))
    assert c.get("/api/health").json()["status"] == "no-log"


def test_store_reports_a_missing_log_with_a_usable_message(tmp_path):
    with pytest.raises(FileNotFoundError) as e:
        AlertStore(tmp_path / "nope.jsonl").load()
    assert "exp08" in str(e.value), "error should say how to produce the log"


# --------------------------------------------------------------- figures
# The console serves the evidence figures next to the alerts, so a judge asking
# "how do you know?" is answered in the same window. That puts a caller-supplied
# name on the filesystem path, which is the part worth testing.

def test_figures_manifest_lists_only_files_that_exist(client):
    r = client.get("/api/figures")
    assert r.status_code == 200
    for row in r.json():
        assert set(row) >= {"file", "title", "claim"}
        assert row["file"].endswith(".png")
        assert row["claim"].strip(), f"{row['file']} has no claim"


def test_a_declared_figure_is_served_as_png(client):
    figs = client.get("/api/figures").json()
    if not figs:
        pytest.skip("no figures generated in this checkout")
    r = client.get("/figures/" + figs[0]["file"])
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("image/png")
    assert r.content[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.parametrize("name", [
    "../../../../Windows/win.ini",
    "..%2f..%2fsecrets.txt",
    "....//results/exp08_evidence.jsonl",
    "exp08_evidence.jsonl",          # real file, but not a declared figure
    "fig99_does_not_exist.png",
])
def test_undeclared_names_are_refused(client, name):
    """An allowlist, not a prefix check.

    The route takes a caller-supplied name straight to the filesystem. Only the
    names the manifest declares are served, so traversal has nothing to reach
    even when the target exists.
    """
    r = client.get("/figures/" + name)
    assert r.status_code in (404, 400), f"{name!r} was not refused"
    assert b"PNG" not in r.content[:8]
