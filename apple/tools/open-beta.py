# /// script
# requires-python = ">=3.11"
# dependencies = ["pyjwt[crypto]>=2.8"]
# ///
"""Give an uploaded build to the public TestFlight group and submit it for beta review.

    uv run apple/tools/open-beta.py <build-number> [what-to-test]

Uploading only reaches internal testers. External testers, who join through
the "open beta" group's public link, get a build only once it is in that group
and Apple's beta review has passed it, so every upload is handed on here. It
waits for App Store Connect to finish processing each build with that number
(iOS and tvOS share one), sets its "What to Test" text (default: the subject
of the last commit) and adds it to the group. Run again on the same build, it
changes nothing. Reads APPLE_API_KEY_PATH, APPLE_API_KEY_ID and
APPLE_API_ISSUER_ID, as the archive does.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import jwt

API = "https://api.appstoreconnect.apple.com/v1"
GROUP = "open beta"
APPEAR = 15 * 60
PROCESS = 60 * 60
POLL = 30


def token() -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": os.environ["APPLE_API_ISSUER_ID"],
            "iat": now,
            "exp": now + 1200,
            "aud": "appstoreconnect-v1",
        },
        Path(os.environ["APPLE_API_KEY_PATH"]).read_text(),
        algorithm="ES256",
        headers={"kid": os.environ["APPLE_API_KEY_ID"]},
    )


def call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body else None,
        headers={
            "Authorization": f"Bearer {token()}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            text = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"{method} {path}: HTTP {e.code} {e.read().decode(errors='replace')}"
        ) from None
    return json.loads(text) if text else {}


def get(path: str, **query: str) -> list:
    return call("GET", f"{path}?{urllib.parse.urlencode(query)}")["data"]


def main() -> None:
    if not 2 <= len(sys.argv) <= 3:
        sys.exit(__doc__)
    build = sys.argv[1]
    notes = (
        sys.argv[2]
        if len(sys.argv) == 3
        else subprocess.check_output(["git", "log", "-1", "--format=%s"], text=True)
    )
    notes = re.sub(r"\s*\(#\d+\)$", "", notes.strip())

    project = (Path(__file__).parent.parent / "App/project.yml").read_text()
    bundle = re.search(r"^ *SBR_BUNDLE_ID: *(\S+)", project, re.MULTILINE)[1]
    app = get("/apps", **{"filter[bundleId]": bundle})[0]["id"]
    group = next(
        g for g in get(f"/apps/{app}/betaGroups") if g["attributes"]["name"] == GROUP
    )["id"]
    locale = get(f"/apps/{app}/betaAppLocalizations")[0]["attributes"]["locale"]

    start = time.monotonic()
    while True:
        builds = get("/builds", **{"filter[app]": app, "filter[version]": build})
        states = {b["id"]: b["attributes"]["processingState"] for b in builds}
        if any(s in ("FAILED", "INVALID") for s in states.values()):
            sys.exit(f"build {build} failed processing: {states}")
        if builds and all(s == "VALID" for s in states.values()):
            break
        waited = time.monotonic() - start
        if waited > (PROCESS if builds else APPEAR):
            sys.exit(
                f"build {build} not processed after {waited / 60:.0f} min: {states or 'not uploaded'}"
            )
        time.sleep(POLL)

    for b in builds:
        platform = call("GET", f"/builds/{b['id']}/preReleaseVersion")["data"][
            "attributes"
        ]["platform"]
        localizations = get(f"/builds/{b['id']}/betaBuildLocalizations")
        mine = next(
            (l for l in localizations if l["attributes"]["locale"] == locale), None
        )
        if mine:
            call(
                "PATCH",
                f"/betaBuildLocalizations/{mine['id']}",
                {
                    "data": {
                        "type": "betaBuildLocalizations",
                        "id": mine["id"],
                        "attributes": {"whatsNew": notes},
                    }
                },
            )
        else:
            call(
                "POST",
                "/betaBuildLocalizations",
                {
                    "data": {
                        "type": "betaBuildLocalizations",
                        "attributes": {"locale": locale, "whatsNew": notes},
                        "relationships": {
                            "build": {"data": {"type": "builds", "id": b["id"]}}
                        },
                    }
                },
            )
        call(
            "POST",
            f"/betaGroups/{group}/relationships/builds",
            {"data": [{"type": "builds", "id": b["id"]}]},
        )
        if call("GET", f"/builds/{b['id']}/betaAppReviewSubmission").get("data"):
            print(
                f"{platform} {build}: in {GROUP!r}, already submitted for beta review"
            )
            continue
        call(
            "POST",
            "/betaAppReviewSubmissions",
            {
                "data": {
                    "type": "betaAppReviewSubmissions",
                    "relationships": {
                        "build": {"data": {"type": "builds", "id": b["id"]}}
                    },
                }
            },
        )
        print(f"{platform} {build}: in {GROUP!r}, submitted for beta review")


if __name__ == "__main__":
    main()
