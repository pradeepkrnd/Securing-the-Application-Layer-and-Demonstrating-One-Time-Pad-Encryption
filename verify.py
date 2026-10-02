"""Real HTTP checks against Java source-file mode. Python 3 standard library only."""
import concurrent.futures
import http.client
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
KEY = "disposable-local-test-key-2026"

def start():
    process = subprocess.Popen(
        ["java", "--add-modules", "jdk.httpserver", "Layer7Protection.java", "0"],
        cwd=ROOT, env={**os.environ, "APP_API_KEY": KEY},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = process.stdout.readline().strip()
    if not line.startswith("Listening on "):
        raise RuntimeError(line + process.stderr.read())
    return process, int(line.rsplit(":", 1)[1])

def request(port, method="POST", body=b'{"username":"pradeepk"}',
            key=KEY, media="application/json", path="/api/profile"):
    headers = {}
    if key is not None: headers["X-API-Key"] = key
    if media is not None: headers["Content-Type"] = media
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body, headers)
    response = conn.getresponse()
    status, data, hdr = response.status, response.read(), dict(response.getheaders())
    conn.close()
    return status, data, hdr

def stop(process):
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()

def main():
    cases = [
        ("Valid username", {}, 200),
        ("Missing API key", {"key": None}, 401),
        ("Incorrect API key", {"key": "incorrect"}, 401),
        ("GET method", {"method": "GET"}, 405),
        ("Wrong media type", {"media": "text/plain"}, 415),
        ("Misleading JSON prefix", {"media": "application/json-evil"}, 415),
        ("Script-like username", {"body": b'{"username":"<script>"}'}, 400),
        ("Extra JSON field", {"body": b'{"username":"abc","role":"admin"}'}, 400),
        ("Duplicate JSON field", {"body": b'{"username":"abc","username":"xyz"}'}, 400),
        ("Malformed UTF-8", {"body": b'{"username":"\xffab"}'}, 400),
        ("Oversized body", {"body": b'x' * 1025}, 413),
        ("Exact path required", {"path": "/api/profile/extra"}, 404),
        ("Minimum length accepted", {"body": b'{"username":"abc"}'}, 200),
        ("Maximum length accepted", {"body": b'{"username":"' + b'a'*32 + b'"}'}, 200),
        ("Short username rejected", {"body": b'{"username":"ab"}'}, 400),
        ("Long username rejected", {"body": b'{"username":"' + b'a'*33 + b'"}'}, 400),
        ("UTF-8 media parameter", {"media": "application/json; charset=UTF-8"}, 200),
    ]
    process = None
    try:
        for i, (name, kwargs, expected) in enumerate(cases):
            if i % 4 == 0:
                if process is not None: stop(process)
                process, port = start()
            status, data, headers = request(port, **kwargs)
            assert status == expected, (name, status, expected)
            assert headers.get("X-content-type-options") == "nosniff"
            assert headers.get("Cache-control") == "no-store"
            assert headers.get("Content-security-policy") == "default-src 'none'"
            assert headers.get("X-frame-options") == "DENY"
            assert headers.get("Referrer-policy") == "no-referrer"
            if status == 405: assert headers.get("Allow") == "POST"
            if status == 401: assert "Www-authenticate" in headers
            if name == "Valid username":
                assert data == b'{"status":"accepted","username":"pradeepk"}'
            print(f"PASS {name}: HTTP {status}", flush=True)
    finally:
        if process is not None: stop(process)
    process, port = start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(lambda _: request(port), range(10)))
        codes = [r[0] for r in results]
        assert codes.count(200) == 5 and codes.count(429) == 5, codes
        assert all(1 <= int(h["Retry-after"]) <= 60 for c, _, h in results if c == 429)
        print("PASS concurrent quota: 5 HTTP 200 and 5 HTTP 429")
    finally: stop(process)
    no_key_env = dict(os.environ)
    no_key_env.pop("APP_API_KEY", None)
    missing = subprocess.run(["java", "--add-modules", "jdk.httpserver", "Layer7Protection.java"],
                             cwd=ROOT, env=no_key_env, capture_output=True, text=True)
    assert missing.returncode == 1 and "at least 24" in missing.stderr
    print("PASS missing startup secret: exit 1")
    print("TOTAL: 19 checks passed; security headers checked on 17 responses")
    otp = subprocess.run(["java", "OneTimePad.java"], cwd=ROOT, capture_output=True, text=True, check=True)
    print("\nONE TIME PAD VERIFICATION")
    print(otp.stdout, end="")
    (ROOT / "otp-output.txt").write_text(otp.stdout)

if __name__ == "__main__": main()
