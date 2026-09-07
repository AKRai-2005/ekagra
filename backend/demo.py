"""One command to bring the whole sensor up.

    python demo.py

Why this file exists
--------------------
Before it, showing the system took four steps in the right order: run exp08,
which writes the evidence log and a console snapshot, then start the API, then
open the console, and hope the snapshot was not stale. That is a fine workflow
at a desk and a bad one at 3am in a nodal centre with a judge waiting.

So: one command, no arguments, no network. It checks for an evidence log,
generates one if missing, starts the read-only API on loopback, and opens the
console. Anything it cannot do, it says plainly rather than serving an empty
page.

Deliberately offline
--------------------
Nothing here reaches the internet. The console has no CDN, the API binds
127.0.0.1, and the sensor runs on generated traffic unless pointed at a corpus.
That is the deployment this project is about, and a demo that needed a network
would be arguing against its own premise.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

EVIDENCE = ROOT / "results" / "exp08_evidence.jsonl"
CONSOLE_DATA = ROOT.parent / "frontend" / "data.js"
SENSOR_RUN = ROOT / "experiments" / "exp08_evidence_console.py"

BANNER = r"""
   ___ _  __   _   ___ ___    _
  | __| |/ /  /_\ / __| _ \  /_\     enclave console
  | _|| ' <  / _ \ (_ |   / / _ \    SIH26145 - NTRO
  |___|_|\_\/_/ \_\___|_|_\/_/ \_\   read-only, air-gapped
"""

TALK_TRACK = """
  What to show, in order
  ----------------------
  1. The header       the LIVE badge means the console is reading the API, not
                      a saved file. One-way tap, {latency}s latency, packets/s.
  2. Replay           400 alerts stream in over server-sent events, in the order
                      they were logged.
  3. An alert         click one. The evidence panel is the point: what was
                      observed, which model, the feature vector, the decision
                      path, and the hash linking it to the previous alert.
  4. Verify chain     the browser re-derives every digest itself, then asks the
                      server separately. Two implementations, two languages, one
                      verdict - it does not display a flag the server sent.
  5. Tamper           alter one alert and verify again. That entry breaks, every
                      entry after it breaks, and the two verifiers now disagree,
                      which is exactly what catches evidence altered in transit.
  6. Reset            back to the intact log.
  7. Findings tab     the ten figures behind every number claimed here, each
                      with the claim it carries. Three of them report a
                      prediction our own experiments refuted.

  The question this answers is not "did you notice the attack" - it is
  "can you prove this alert has not been altered since it was raised".
"""


def run_sensor(force: bool = False) -> bool:
    """Generate the evidence log if it is missing."""
    if EVIDENCE.exists() and CONSOLE_DATA.exists() and not force:
        size = EVIDENCE.stat().st_size / 1e6
        print(f"  [ok]   evidence log present ({size:.0f} MB)")
        return True

    why = "regenerating on request" if force else "no evidence log yet"
    print(f"  [..]   {why} - running the sensor (about 40s)")
    proc = subprocess.run([sys.executable, "-u", str(SENSOR_RUN)],
                          cwd=str(ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        print("  [!!]   sensor run failed. Last lines:\n")
        print("\n".join(proc.stdout.strip().splitlines()[-15:]))
        print(proc.stderr.strip()[-800:])
        return False

    for line in proc.stdout.splitlines():
        if "entries" in line and "chain" in line:
            print(f"  [ok]   {line.strip()}")
        elif "packets observed" in line:
            print(f"  [ok]   {line.strip()}")
    return EVIDENCE.exists()


def open_when_ready(url: str, timeout: float = 20.0) -> None:
    """Open the browser once the server answers, not before."""
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "api/health", timeout=1) as r:
                if r.status == 200:
                    break
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    else:
        print(f"  [!!]   server did not answer within {timeout:.0f}s")
        return
    print(f"  [ok]   console ready at {url}")
    try:
        webbrowser.open(url)
    except Exception:
        print("  [--]   could not open a browser; use the URL above")


def main() -> int:
    ap = argparse.ArgumentParser(description="Bring up the EKAGRA console.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1",
                    help="loopback by default; an enclave console should not "
                         "bind a public interface without someone typing it")
    ap.add_argument("--regenerate", action="store_true",
                    help="re-run the sensor even if an evidence log exists")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    # Line-buffer stdout: Python block-buffers when it is not a terminal, so
    # `python demo.py | tee run.log` showed nothing until the server stopped.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:      # pragma: no cover - very old interpreters
        pass

    print(BANNER)
    if not run_sensor(force=args.regenerate):
        print("\n  Could not produce an evidence log. Nothing to show.")
        return 1

    figs = ROOT / "results" / "figures.json"
    if figs.exists():
        import json as _json
        n = len(_json.loads(figs.read_text()))
        print(f"  [ok]   {n} evidence figures available under the Findings tab")
    else:
        print("  [--]   no figures yet - run experiments/make_figures_pipeline.py")

    from ekagra.api.server import create_app
    import uvicorn

    url = f"http://{args.host}:{args.port}/"
    if not args.no_browser:
        threading.Thread(target=open_when_ready, args=(url,), daemon=True).start()

    print(f"  [..]   serving on {url}  (ctrl-c to stop)")
    print(TALK_TRACK.format(latency=75))

    cfg = uvicorn.Config(create_app(), host=args.host, port=args.port,
                         log_level="warning")
    try:
        uvicorn.Server(cfg).run()
    except KeyboardInterrupt:
        pass
    print("\n  stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
