# /// script
# requires-python = ">=3.11"
# dependencies = ["pyjwt[crypto]>=2.8"]
# ///
"""Install App Store provisioning profiles by name from App Store Connect.

    uv run apple/tools/fetch-profiles.py "sbr App Store" "sbr tunnel App Store"

Release builds for iOS sign manually (see App/project.yml), so a machine that
has never opened Xcode with the team's account, such as a CI runner, needs the
profiles installed before it can archive. Reads APPLE_API_KEY_PATH,
APPLE_API_KEY_ID and APPLE_API_ISSUER_ID, as the archive does.
"""

import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import jwt

API = "https://api.appstoreconnect.apple.com/v1"
DIRS = [
    # Xcode 16 and later read this one; older ones the second.
    Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles",
    Path.home() / "Library/MobileDevice/Provisioning Profiles",
]


def token() -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": os.environ["APPLE_API_ISSUER_ID"], "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        Path(os.environ["APPLE_API_KEY_PATH"]).read_text(),
        algorithm="ES256",
        headers={"kid": os.environ["APPLE_API_KEY_ID"]},
    )


def profile(name: str, auth: str) -> dict:
    query = urllib.parse.urlencode({"filter[name]": name, "filter[profileState]": "ACTIVE"})
    req = urllib.request.Request(f"{API}/profiles?{query}", headers={"Authorization": f"Bearer {auth}"})
    with urllib.request.urlopen(req) as r:
        found = [p for p in json.load(r)["data"] if p["attributes"]["name"] == name]
    if not found:
        sys.exit(f"no active profile named {name!r}")
    # The newest, should a regenerated one sit beside an expiring one.
    return max(found, key=lambda p: p["attributes"]["expirationDate"])["attributes"]


def main() -> None:
    auth = token()
    for d in DIRS:
        d.mkdir(parents=True, exist_ok=True)
    for name in sys.argv[1:]:
        p = profile(name, auth)
        content = base64.b64decode(p["profileContent"])
        for d in DIRS:
            (d / f"{p['uuid']}.mobileprovision").write_bytes(content)
        print(f"installed {name!r} ({p['uuid']}, expires {p['expirationDate']})")


if __name__ == "__main__":
    main()
