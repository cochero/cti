"""A minimal OpenAI-compatible chat server for live-testing the LLM path.

Implements POST /v1/chat/completions. The "model" is deliberately simple:
it reads the user prompt (which contains the untrusted document between
<<<DOC>>> markers), regex-extracts CVE ids and a few actor names, and
returns them as a JSON array in the exact candidate shape. That exercises
the FULL production path — HTTP client, response parsing, LLMExtractor
JSON handling, and the schema gate — against a real socket, without
depending on an external API key.

Run standalone:  python -m tests_live.fake_llm_server [port]
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_ACTORS = ("Lazarus", "APT28", "APT29", "FIN7", "Sandworm")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        user = next((m["content"] for m in body.get("messages", [])
                     if m.get("role") == "user"), "")
        doc = user.split("<<<DOC>>>")[1].split("<<<DOC>>>")[0] \
            if "<<<DOC>>>" in user else user

        candidates = []
        for cve in dict.fromkeys(_CVE.findall(doc)):
            candidates.append({
                "subject_type": "CVE", "subject_value": cve,
                "assertion": "mentioned", "object_value": None,
                "extraction_confidence_millis": 850,
                "attack_technique_ids": [],
            })
        for actor in _ACTORS:
            if re.search(r"\b%s\b" % re.escape(actor), doc):
                candidates.append({
                    "subject_type": "THREAT_ACTOR", "subject_value": actor,
                    "assertion": "mentioned", "object_value": None,
                    "extraction_confidence_millis": 800,
                    "attack_technique_ids": [],
                })

        resp = {
            "id": "chatcmpl-fake", "object": "chat.completion",
            "model": body.get("model", "fake"),
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant",
                            "content": json.dumps(candidates)},
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                      "total_tokens": 0},
        }
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence per-request noise
        pass


def serve(port: int = 8123) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), Handler)
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
    print("fake llm server on :%d" % port, file=sys.stderr)
    serve(port)
    import time
    while True:
        time.sleep(3600)
