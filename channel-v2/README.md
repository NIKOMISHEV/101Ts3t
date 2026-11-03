# Offline channel verification release v2

Since 3 November 2026 a channel test on dothat.quest gives the agent the
prompt of the chosen channel: the unchanged v1.0-draft prompt plus one
paragraph that names the payment channel. It never names the seller, a
website, a URL, a server or a link. channel-v2 verifies such runs, one evidence
layer per channel under [`channels-v2/`](../channels-v2/README.md).

channel-v1 (neutral prompt, channel hidden until the run ended), its frozen
layers under `channels/` and its run records stay unchanged and valid.

## Install and test

Use Python 3.12 in an isolated environment. Evidence verification itself makes
no network requests.

```sh
python -m venv .venv
python -m pip install --require-hashes -r channel-v2/requirements.lock
python -m unittest discover -s channel-v2/tests -v
python -m unittest discover -s channel-support-v2/tests -v
```

`vendor/` holds the verifier deployed at api.dothat.quest (release
20261103-channel-v2), with the seven prompt templates in `vendor/prompts/`.
The hashes are in `vendor-manifest.json`. The tests use synthetic keys and
invented transactions only.

## Replay a recorded run

Each run folder `channels-v2/<channel>/runs/<challenge>/` contains the issued
challenge with its exact prompt, the revealed declaration, its RFC 3161 token,
the public proof (for a base PASS), the seller-signed channel artifact, the
offline result and a Sigstore bundle over its manifest.

```sh
openssl ts -verify -digest <commitment> -in declaration-timestamp.tsr -CAfile <system trust store>
openssl ts -reply -in declaration-timestamp.tsr -text
python channel-v2/verify_channel_release.py --challenge-id <challenge> --channel <channel> --base-status PASS --declaration declaration.json --proof proof.json --channel-artifact channel.json --declaration-time <RFC 3161 time> --not-before <verified attestation time of the channel layer> --layer-sha256 <sha256 of channels-v2/<channel>/freeze/manifest.json> --output /new/path/verification.json
```

The record workflow takes `--not-before` only from `gh attestation verify` of
the layer commitment, and `--declaration-time` only from `openssl ts -verify`.
