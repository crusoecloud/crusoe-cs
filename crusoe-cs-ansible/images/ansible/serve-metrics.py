#!/usr/bin/env python3
"""Generic textfile metrics file-server for the crusoe-mitigator chart.

Serves every *.prom file in a directory (node_exporter textfile
convention) as one Prometheus exposition on GET /metrics. Generators
(metrics.sh per mitigation, the pod-netns reconciler) own their own
files; this server is CVE-agnostic and serves whatever is there.

HELP/TYPE lines are emitted once per metric family — first-seen wins;
a duplicate family logs a warning to stderr and never fails the
scrape (a Prometheus parser rejects duplicate HELP lines, which
would lose ALL metrics, not one).

Files are written atomically by the generators (tmp+mv), so a read
either sees the old or the new content, never a torn write.

Usage: serve-metrics.py --dir DIR --port 19698
"""

import argparse
import http.server
import os
import sys


def _split_labels(label_part):
    """Split a label string on commas OUTSIDE double quotes (a quoted
    value may contain a comma — the naive split breaks there)."""
    parts, buf, in_quotes = [], [], False
    for ch in label_part:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == "," and not in_quotes:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def make_handler(metrics_dir):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path != "/metrics":
                self.send_error(404)
                return
            body = self.exposition(metrics_dir)
            if "format=json" in query:
                body = self.json_view(body)
                content_type = "application/json"
            else:
                content_type = "text/plain; version=0.0.4"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        @staticmethod
        def json_view(exposition):
            """The exposition as a native dict — the Ansible/tooling
            path (no text parsing on the consumer side). Labeled
            samples (mode{...}) nest under the family name; unlabeled
            samples are scalars. HELP/TYPE lines are skipped."""
            import json

            out = {}
            for line in exposition.splitlines():
                if not line or line.startswith("#"):
                    continue
                name, _, value = line.rpartition(" ")
                if "{" in name:
                    family, _, label_part = name.partition("{")
                    # Label parsing: split on commas OUTSIDE quotes (a
                    # quoted value may contain a comma).
                    labels = {}
                    for kv in _split_labels(label_part.rstrip("}")):
                        if "=" in kv:
                            k, _, v = kv.partition("=")
                            labels[k.strip()] = v.strip('"')
                    try:
                        num = float(value)
                    except ValueError:
                        continue
                    fam = out.setdefault(family, {})
                    if len(labels) == 1:
                        # Single label: keyed by the label VALUE (the
                        # enum shape: mode: {observe: 1, enforce: 0}).
                        fam[next(iter(labels.values()))] = num
                    else:
                        # Multi-label: keyed by the IDENTIFYING label
                        # (netns for the reconciler's per-netns
                        # counters), with the other labels preserved —
                        # no dimension is lost to a collision.
                        ident = labels.get("netns") or next(iter(labels.values()))
                        rest = {k: v for k, v in labels.items() if k != "netns"}
                        entry = fam.setdefault(ident, {} if rest else num)
                        if rest:
                            entry.update(rest)
                            entry["value"] = num
                else:
                    try:
                        out[name] = float(value)
                    except ValueError:
                        pass
            return json.dumps(out)

        def exposition(self, directory):
            seen_meta = {}
            samples = []
            try:
                names = sorted(os.listdir(directory))
            except OSError:
                return ""
            for name in names:
                if not name.endswith(".prom"):
                    continue
                path = os.path.join(directory, name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        lines = fh.read().splitlines()
                except OSError:
                    continue
                for line in lines:
                    if line.startswith(("# HELP", "# TYPE")):
                        # "# HELP <family> <doc>" / "# TYPE <family> <type>"
                        # — split() yields ['#', 'HELP', family, ...].
                        # Dedupe per (kind, family): a family's HELP and
                        # its TYPE are distinct meta lines; only a SECOND
                        # file re-declaring the same (kind, family) is a
                        # duplicate.
                        parts = line.split()
                        if len(parts) < 4:
                            # A malformed meta line (e.g. a bare
                            # '# HELP <family>' with no description) is
                            # passed through, not silently eaten — the
                            # consumer sees what the generator wrote
                            # (the bot review's #4).
                            samples.append(line)
                            continue
                        meta_key = (parts[1], parts[2])
                        if meta_key in seen_meta:
                            # IDENTICAL re-declaration (same kind, family,
                            # AND payload) is the normal multi-generator
                            # shape — e.g. the metrics script and the
                            # reconciler both declare matched_packets_total.
                            # The kubelet probes GET /metrics every 10s, so
                            # warning here was ~11.5k lines/day/pod of noise
                            # (found live). Dedupe silently; only a CONFLICT
                            # (a different type/doc for one family — a
                            # generator bug) warns, which is the case
                            # first-seen-wins exists to protect.
                            if seen_meta[meta_key] != line:
                                print(
                                    f"serve-metrics: duplicate {parts[1]} "
                                    f"for family {parts[2]} (from {name}); "
                                    "keeping first-seen",
                                    file=sys.stderr,
                                )
                            continue
                        seen_meta[meta_key] = line
                        samples.append(line)
                    elif line.strip():
                        samples.append(line)
            return "\n".join(samples) + ("\n" if samples else "")

        def log_message(self, fmt, *args):
            # Quiet access logs — vmagent scrapes every 150s.
            pass

    return Handler


def log_startup(metrics_dir, port):
    """One startup line to stderr — the reconciler's pattern. The
    server is deliberately quiet (access logs suppressed; vmagent
    scrapes every 150s), but TOTAL silence is indistinguishable
    from a hang before bind: this line is what lets an operator
    reading pod logs tell 'serving' from 'dead at startup' without
    external probes. Emitted BEFORE serve_forever so a bind failure
    still leaves the line in the log."""
    try:
        prom_files = [f for f in os.listdir(metrics_dir) if f.endswith(".prom")]
    except OSError:
        prom_files = []
    print(
        f"serve-metrics: serving {len(prom_files)} prom file(s) from "
        f"{metrics_dir} on :{port}",
        file=sys.stderr,
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="textfile directory")
    parser.add_argument("--port", type=int, default=19698)
    args = parser.parse_args()
    log_startup(args.dir, args.port)
    with http.server.ThreadingHTTPServer(
        ("0.0.0.0", args.port), make_handler(args.dir)
    ) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
