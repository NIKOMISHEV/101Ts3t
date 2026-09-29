"""Public-only publication helpers. No challenge issuance, credentials or payment API.

The authenticated timestamp comes ONLY from a successful, identity-constrained
`gh attestation verify` call, never from an unverified bundle or its predicate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "NIKOMISHEV/101Ts3t"
FREEZE = ROOT / "route-attestations/v1"
SPEC_TYPE = "https://dothat.quest/attestations/route-specification/v1"
PASS_TYPE = "https://dothat.quest/attestations/route-qualified-commerce/v1"
WORKFLOWS = ("route-ci.yml", "route-freeze.yml", "route-anchor.yml")
PROTOCOLS = ("bd-commerce/1", "acp/2026-04-17", "ucp/2026-08-25", "ucp/2026-04-08")
MAX_BYTES = 128 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with path.open("xb") as handle:
        handle.write(data)


def load(path):
    return json.loads(path.read_bytes())


def check_history(root=ROOT):
    baseline = load(root / "workflow-support/historical-files.json")
    for name, expected in baseline["files"].items():
        require(digest((root / name).read_bytes()) == expected, "Historical file changed: " + name)


def manifest(source_revision, root=ROOT):
    require(re.fullmatch(r"[a-f0-9]{40}", source_revision), "Invalid source revision")
    files = []
    for directory in ("route-v1", "workflow-support"):
        for path in (root / directory).rglob("*"):
            # Python-generated cache files are not release inputs.
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "Release contains a symlink")
            if path.is_file():
                files.append(path)
    files.extend(root / ".github/workflows" / name for name in WORKFLOWS)
    files.append(root / ".gitattributes")
    return {"release": "route-v1", "source_revision": source_revision,
            "files": {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in sorted(files)}}


def check_manifest(root=ROOT):
    frozen = load(root / "route-attestations/v1/manifest.json")
    require(frozen == manifest(frozen["source_revision"], root), "Frozen route-v1 inputs changed; create a new version")
    check_history(root)
    return frozen


def parse_time(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value), "Invalid trusted timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verified_timestamp(results, subject_digest, predicate_type):
    # Input must be the stdout of gh's successful verification subprocess.
    # Raw attestation fields, signer-chosen predicate dates and CurrentTime do not qualify.
    require(isinstance(results, list) and len(results) == 1, "Expected exactly one verified attestation")
    verified = results[0]["verificationResult"]
    statement = verified["statement"]
    require(statement["predicateType"] == predicate_type, "Wrong verified predicate type")
    require(len(statement["subject"]) == 1 and
            statement["subject"][0]["digest"] == {"sha256": subject_digest}, "Wrong verified subject")
    timestamps = verified["verifiedTimestamps"]
    require(isinstance(timestamps, list) and timestamps, "Missing externally verified timestamp")
    parsed = []
    for item in timestamps:
        require(item["type"] in ("Tlog", "TimestampAuthority"), "Timestamp is not externally authenticated")
        observed = parse_time(item["timestamp"])
        if item["type"] == "Tlog":
            parsed.append(observed)
    require(parsed, "Missing verified transparency-log inclusion time")
    # The latest verified log time is conservative for pre-event ordering.
    selected = max(parsed)
    require(selected <= datetime.now(timezone.utc), "Verified timestamp is in the future")
    return selected.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def verify_attestation(subject, bundle, workflow, predicate_type, source_revision):
    completed = subprocess.run([
        "gh", "attestation", "verify", str(subject), "--bundle", str(bundle),
        "--repo", REPO, "--signer-workflow", REPO + "/.github/workflows/" + workflow,
        "--source-ref", "refs/heads/main", "--source-digest", source_revision,
        "--deny-self-hosted-runners", "--predicate-type", predicate_type, "--format", "json",
    ], check=True, capture_output=True, text=True, timeout=120)
    return verified_timestamp(json.loads(completed.stdout), digest(subject.read_bytes()), predicate_type)


def authenticate_freeze():
    frozen = check_manifest()
    time = verify_attestation(FREEZE / "manifest.json", FREEZE / "manifest.sigstore.json",
                             "route-freeze.yml", SPEC_TYPE, frozen["source_revision"])
    return {"manifest_sha256": digest((FREEZE / "manifest.json").read_bytes()),
            "specification_sha256": frozen["files"]["route-v1/SPECIFICATION.md"],
            "attested_at": time, "source_revision": frozen["source_revision"]}


def prepare_freeze():
    check_history()
    if FREEZE.exists():
        authenticate_freeze()
        print("Existing route-v1 freeze verified; no replacement.")
        fresh = False
    else:
        frozen = manifest(os.environ["GITHUB_SHA"])
        FREEZE.mkdir(parents=True)
        write_new(FREEZE / "manifest.json", encode(frozen))
        write_new(FREEZE / "predicate.json", encode({"release": "route-v1", "assertsTransaction": False,
            "assertsPass": False, "purpose": "Pre-event commitment to route rules, public trust, verifier and workflows"}))
        fresh = True
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write("fresh=" + str(fresh).lower() + "\n")


def preserve_freeze():
    write_new(FREEZE / "manifest.sigstore.json", Path(os.environ["BUNDLE_PATH"]).read_bytes())
    verified = authenticate_freeze()
    write_new(FREEZE / "verification.json", encode(verified))
    write_new(FREEZE / "README.md", (
        "# Route-v1 pre-event commitment\n\nRules, verifier, trust registry and workflows are bound by manifest.json.\n"
        "The Sigstore bundle authenticates this manifest and its GitHub workflow identity.\n"
        "This is not evidence of a purchase or a route PASS.\n\n"
        "Run `python workflow-support/release.py verify-freeze` to verify the bundle and current input hashes.\n"
        "GitHub CLI and the dependencies in route-v1/requirements.lock are required.\n").encode())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Public evidence redirects are forbidden")


def download(kind, identifier):
    if kind == "proof":
        require(re.fullmatch(r"qst_[a-f0-9]{32}", identifier), "Invalid challenge")
        url = "https://api.dothat.quest/api/proofs/" + identifier
    elif kind == "route":
        require(re.fullmatch(r"evt_[a-f0-9]{32}", identifier), "Invalid event")
        url = "https://branddesign.host/commerce/v1/evidence/" + identifier + "/route"
    else:
        raise ValueError("Unsupported evidence kind")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "101Ts3t-route-verifier/1"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, "Wrong public evidence response")
        data = response.read(MAX_BYTES + 1)
    require(0 < len(data) <= MAX_BYTES, "Public evidence exceeds size limit")
    return data


def prepare_run():
    challenge, protocol = os.environ["CHALLENGE_ID"], os.environ["EXPECTED_PROTOCOL"]
    require(re.fullmatch(r"qst_[a-f0-9]{32}", challenge), "Invalid challenge")
    require(protocol in PROTOCOLS, "Unsupported protocol")
    require(not (ROOT / "records" / challenge).exists(), "Historical base record cannot become a new route test")
    destination = ROOT / "route-records" / challenge
    require(not destination.exists(), "Route record already exists")
    committed = authenticate_freeze()
    proof_bytes = download("proof", challenge)
    proof = json.loads(proof_bytes)
    event = proof["provider_artifact"]["payload"]["provider_event_reference"]
    route_bytes = download("route", event)
    # Untrusted downloads stay outside the worktree until the offline replay succeeds.
    scratch = Path(os.environ["RUNNER_TEMP"]) / "route-evidence"
    scratch.mkdir()
    write_new(scratch / "proof.json", proof_bytes)
    write_new(scratch / "route.json", route_bytes)
    subprocess.run([sys.executable, str(ROOT / "route-v1/verify_release.py"),
        "--challenge-id", challenge, "--expected-protocol", protocol,
        "--proof", str(scratch / "proof.json"), "--route", str(scratch / "route.json"),
        "--not-before", committed["attested_at"], "--spec-sha256", committed["specification_sha256"],
        "--output", str(scratch / "verification.json")], check=True, timeout=60, capture_output=True)
    result = load(scratch / "verification.json")
    require(result["status"] == "PASS", "Offline replay did not pass")
    destination.mkdir(parents=True)
    for name in ("proof.json", "route.json", "verification.json"):
        write_new(destination / name, (scratch / name).read_bytes())
    write_new(destination / "commitment.json", encode(committed))
    write_new(destination / "manifest.json", encode({"release": "route-v1", "challenge_id": challenge,
        "qualified_protocol": protocol, "source_revision": os.environ["GITHUB_SHA"],
        "files": {p.name: digest(p.read_bytes()) for p in sorted(destination.iterdir())}}))
    write_new(destination / "predicate.json", encode({"release": "route-v1", "challenge_id": challenge,
        "qualified_protocol": protocol, "assertsPass": True, "scope": "Signed merchant route and KYA evidence with offline base PASS replay",
        "doesNotAssert": ["Native platform approval", "Universal agent compatibility", "Private trace reproduced publicly"]}))


def preserve_run():
    challenge = os.environ["CHALLENGE_ID"]
    require(re.fullmatch(r"qst_[a-f0-9]{32}", challenge), "Invalid challenge")
    destination = ROOT / "route-records" / challenge
    write_new(destination / "manifest.sigstore.json", Path(os.environ["BUNDLE_PATH"]).read_bytes())
    attested_at = verify_attestation(destination / "manifest.json", destination / "manifest.sigstore.json",
                                    "route-anchor.yml", PASS_TYPE, os.environ["GITHUB_SHA"])
    write_new(destination / "README.md", (
        "# Route-qualified public evidence\n\nChallenge: " + challenge + "\n\n"
        "The manifest binds the exact public proof, signed route evidence, offline result and pre-event commitment.\n"
        "Sigstore authenticates publication at " + attested_at + ". See route-v1/README.md for independent replay.\n"
        "No private trace, participant identity, credentials or payment token is included.\n").encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check-history", "prepare-freeze", "preserve-freeze", "verify-freeze", "prepare-run", "preserve-run"))
    args = parser.parse_args()
    commands = {"check-history": check_history, "prepare-freeze": prepare_freeze,
        "preserve-freeze": preserve_freeze, "verify-freeze": authenticate_freeze,
        "prepare-run": prepare_run, "preserve-run": preserve_run}
    try:
        result = commands[args.command]()
        if result is not None:
            print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # HTTP bodies, raw artifacts and subprocess stderr may contain untrusted data.
        print("Route publication rejected; no PASS or replacement was authorized.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
