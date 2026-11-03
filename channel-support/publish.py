"""Public-only publication helpers for the channel-v1 evidence layers. No challenge issuance, credentials or payment API.

Each channel has its own layer under channels/<channel>/: its rules (README.md), its own pre-event
Sigstore commitment (freeze/) and one record per ended run (runs/<challenge>/), successful or not.
Authenticated times come ONLY from `gh attestation verify` (Sigstore) and `openssl ts -verify` (RFC 3161).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "NIKOMISHEV/101Ts3t"
CHANNELS = ("mcp", "http-api", "acp", "ucp", "a2a", "browser")
LAYER_TYPE = "https://dothat.quest/attestations/channel-layer/v1"
RUN_TYPE = "https://dothat.quest/attestations/channel-run/v1"
WORKFLOWS = ("channel-ci.yml", "channel-freeze.yml", "channel-record.yml")
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
MAX_BYTES = 128 * 1024
CHALLENGE = re.compile(r"qst_[a-f0-9]{32}")
EVENT = re.compile(r"evt_[a-f0-9]{32}")
GENTIME = re.compile(r"^Time stamp: ([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(\.\d+)? (\d{4}) GMT$", re.M)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


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


def layer(channel):
    require(channel in CHANNELS, "Unknown channel")
    return ROOT / "channels" / channel


def manifest(channel, source_revision, root=ROOT):
    """The exact rules, verifier, trust and workflows one channel layer commits to."""
    require(channel in CHANNELS, "Unknown channel")
    require(re.fullmatch(r"[a-f0-9]{40}", source_revision), "Invalid source revision")
    files = []
    for directory in ("channel-v1", "channel-support"):
        for path in (root / directory).rglob("*"):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "Release contains a symlink")
            if path.is_file():
                files.append(path)
    files.extend(root / ".github/workflows" / name for name in WORKFLOWS)
    files.extend((root / ".gitattributes", root / "channels" / channel / "README.md"))
    return {"release": "channel-v1", "channel": channel, "source_revision": source_revision,
            "files": {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in sorted(files)}}


def check_manifest(channel, root=ROOT):
    frozen = load(root / "channels" / channel / "freeze" / "manifest.json")
    require(frozen == manifest(channel, frozen["source_revision"], root),
            "Frozen channel-v1 inputs changed; publish a new version instead")
    return frozen


def parse_time(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value), "Invalid trusted timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verified_timestamp(results, subject_digest, predicate_type):
    # Input must be the stdout of gh's successful verification subprocess; only Tlog times count.
    require(isinstance(results, list) and len(results) == 1, "Expected exactly one verified attestation")
    verified = results[0]["verificationResult"]
    statement = verified["statement"]
    require(statement["predicateType"] == predicate_type, "Wrong verified predicate type")
    require(len(statement["subject"]) == 1 and statement["subject"][0]["digest"] == {"sha256": subject_digest},
            "Wrong verified subject")
    parsed = [parse_time(item["timestamp"]) for item in verified["verifiedTimestamps"] if item["type"] == "Tlog"]
    require(parsed, "Missing verified transparency-log inclusion time")
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


def authenticate_layer(channel):
    frozen = check_manifest(channel)
    freeze = layer(channel) / "freeze"
    time = verify_attestation(freeze / "manifest.json", freeze / "manifest.sigstore.json", "channel-freeze.yml",
                              LAYER_TYPE, frozen["source_revision"])
    return {"channel": channel, "manifest_sha256": digest((freeze / "manifest.json").read_bytes()),
            "attested_at": time, "source_revision": frozen["source_revision"]}


def output(name, value):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write(name + "=" + value + "\n")


def prepare_freeze():
    channel = os.environ["CHANNEL"]
    freeze = layer(channel) / "freeze"
    if freeze.exists():
        authenticate_layer(channel)
        print("Existing " + channel + " layer commitment verified; no replacement.")
        output("fresh", "false")
        return
    frozen = manifest(channel, os.environ["GITHUB_SHA"])
    freeze.mkdir(parents=True)
    write_new(freeze / "manifest.json", encode(frozen))
    write_new(freeze / "predicate.json", encode({"release": "channel-v1", "channel": channel, "assertsTransaction": False,
        "assertsPass": False, "purpose": "Pre-event commitment to the rules, verifier, trust and workflows of one channel layer"}))
    output("fresh", "true")


def preserve_freeze():
    channel = os.environ["CHANNEL"]
    freeze = layer(channel) / "freeze"
    write_new(freeze / "manifest.sigstore.json", Path(os.environ["BUNDLE_PATH"]).read_bytes())
    verified = authenticate_layer(channel)
    write_new(freeze / "verification.json", encode(verified))
    write_new(freeze / "README.md", (
        "# " + channel + " layer: pre-event commitment\n\n"
        "The rules of this channel, the channel-v1 verifier, trust registry and workflows are bound by manifest.json.\n"
        "The Sigstore bundle authenticates it and its GitHub workflow identity at " + verified["attested_at"] + ".\n"
        "This is not evidence of a purchase or a channel PASS.\n").encode())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Public evidence redirects are forbidden")


def download(url, *, missing_ok=False):
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "101Ts3t-channel-verifier/1"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            require(response.status == 200 and response.geturl() == url, "Wrong public evidence response")
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise
    require(0 < len(data) <= MAX_BYTES, "Public evidence exceeds size limit")
    return data


def openssl_time(text):
    match = GENTIME.search(text)
    require(match is not None and match.group(1) in MONTHS, "Timestamp token has no readable time")
    day, hour, minute, second, year = (int(match.group(i)) for i in (2, 3, 4, 5, 7))
    stamp = datetime(year, MONTHS.index(match.group(1)) + 1, day, hour, minute, second, tzinfo=timezone.utc)
    # A fraction is rounded up, so the time used for "before payment" is never earlier than the token.
    if match.group(6):
        stamp += timedelta(seconds=1)
    return stamp.isoformat().replace("+00:00", "Z")


def verify_rfc3161(commitment, token_path):
    checked = subprocess.run(["openssl", "ts", "-verify", "-digest", commitment, "-in", str(token_path),
                              "-CAfile", CA_BUNDLE], capture_output=True, text=True, timeout=60)
    if checked.returncode != 0 or "Verification: OK" not in checked.stdout:
        return None
    reply = subprocess.run(["openssl", "ts", "-reply", "-in", str(token_path), "-text"],
                           check=True, capture_output=True, text=True, timeout=60)
    return openssl_time(reply.stdout)


def prepare_run():
    challenge = os.environ["CHALLENGE_ID"]
    require(CHALLENGE.fullmatch(challenge), "Invalid challenge")
    api = "https://api.dothat.quest/api/"
    result_bytes = download(api + "channel-results/" + challenge)
    result = json.loads(result_bytes)
    require(result.get("status") != "IN_PROGRESS", "The run has not ended; the channel is still hidden")
    declaration = result["declaration"]
    channel = declaration["channel"]
    require(channel in CHANNELS and declaration["challenge_id"] == challenge, "Invalid declaration")
    destination = layer(channel) / "runs" / challenge
    require(not destination.exists(), "Run record already exists")
    committed = authenticate_layer(channel)
    scratch = Path(os.environ["RUNNER_TEMP"]) / "channel-evidence"
    scratch.mkdir()
    # Untrusted downloads stay outside the worktree until the offline replay has run.
    write_new(scratch / "channel-result.json", result_bytes)
    write_new(scratch / "declaration.json", encode(declaration))
    write_new(scratch / "declaration-timestamp.tsr", base64.b64decode(result["declaration_timestamp"]["response_base64"],
                                                                    validate=True))
    stamp = verify_rfc3161(declaration["commitment"], scratch / "declaration-timestamp.tsr")
    base_status = result["base_status"]
    command = [sys.executable, str(ROOT / "channel-v1/verify_channel_release.py"), "--challenge-id", challenge,
               "--channel", channel, "--base-status", base_status, "--declaration", str(scratch / "declaration.json"),
               "--not-before", committed["attested_at"], "--layer-sha256", committed["manifest_sha256"],
               "--output", str(scratch / "verification.json")]
    if stamp:
        command += ["--declaration-time", stamp]
    if base_status == "PASS":
        proof_bytes = download(api + "proofs/" + challenge)
        write_new(scratch / "proof.json", proof_bytes)
        event = json.loads(proof_bytes)["provider_artifact"]["payload"]["provider_event_reference"]
        require(EVENT.fullmatch(event), "Invalid event")
        artifact = download("https://branddesign.host/commerce/v1/evidence/" + event + "/channel", missing_ok=True)
        command += ["--proof", str(scratch / "proof.json")]
        if artifact is not None:
            write_new(scratch / "channel.json", artifact)
            command += ["--channel-artifact", str(scratch / "channel.json")]
    else:
        record = download(api + "verifications/" + challenge, missing_ok=True)
        if record is not None:
            write_new(scratch / "verification-record.json", record)
    subprocess.run(command, check=True, timeout=60, capture_output=True)
    verification = load(scratch / "verification.json")
    destination.mkdir(parents=True)
    for path in sorted(scratch.iterdir()):
        write_new(destination / path.name, path.read_bytes())
    write_new(destination / "commitment.json", encode(committed))
    write_new(destination / "manifest.json", encode({"release": "channel-v1", "channel": channel, "challenge_id": challenge,
        "status": verification["status"], "source_revision": os.environ["GITHUB_SHA"],
        "files": {p.name: digest(p.read_bytes()) for p in sorted(destination.iterdir())}}))
    write_new(destination / "predicate.json", encode({"release": "channel-v1", "channel": channel, "challenge_id": challenge,
        "status": verification["status"], "reason": verification["reason"], "assertsPass": verification["status"] == "PASS",
        "scope": "Declared channel, its RFC 3161 timestamp and the seller-signed channel evidence, replayed offline",
        "doesNotAssert": ["Native platform approval", "Universal agent compatibility", "Private trace reproduced publicly"]}))
    output("channel", channel)


def preserve_run():
    challenge, channel = os.environ["CHALLENGE_ID"], os.environ["CHANNEL"]
    require(CHALLENGE.fullmatch(challenge), "Invalid challenge")
    destination = layer(channel) / "runs" / challenge
    write_new(destination / "manifest.sigstore.json", Path(os.environ["BUNDLE_PATH"]).read_bytes())
    attested_at = verify_attestation(destination / "manifest.json", destination / "manifest.sigstore.json",
                                    "channel-record.yml", RUN_TYPE, os.environ["GITHUB_SHA"])
    verification = load(destination / "verification.json")
    write_new(destination / "README.md", (
        "# " + channel + " run " + challenge + "\n\n"
        "Result: **" + verification["status"] + "**. " + verification["reason"] + ".\n\n"
        "The manifest binds the revealed declaration, its RFC 3161 token, the public evidence and the offline result.\n"
        "Sigstore authenticates this record at " + attested_at + ". See channel-v1/README.md for independent replay.\n"
        "No private trace, participant identity, credentials or payment token is included.\n").encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare-freeze", "preserve-freeze", "verify-layer", "prepare-run", "preserve-run"))
    args = parser.parse_args()
    commands = {"prepare-freeze": prepare_freeze, "preserve-freeze": preserve_freeze,
                "verify-layer": lambda: authenticate_layer(os.environ["CHANNEL"]),
                "prepare-run": prepare_run, "preserve-run": preserve_run}
    try:
        result = commands[args.command]()
        if result is not None:
            print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # HTTP bodies, raw artifacts and subprocess stderr may contain untrusted data.
        print("Channel publication rejected; nothing was recorded or replaced.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
