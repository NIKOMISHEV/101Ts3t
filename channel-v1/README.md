# Offline channel verification release v1

This directory adds reproducible verification for **future new purchases**,
one evidence layer per payment channel. It makes no claim that a channel test
has already happened. Read [the specification](SPECIFICATION.md) and the layer
of your channel under [`channels/`](../channels/README.md) before a run.

The original test, its PASS record, route-v1 and the channel cards in
`channels/CHANNELS.md` remain unchanged historical records.

## Install and test

Use Python 3.12 in an isolated environment. Evidence verification itself makes
no network requests.

```sh
python -m venv .venv
python -m pip install --require-hashes -r channel-v1/requirements.lock
python -m unittest discover -s channel-v1/tests -v
python -m unittest discover -s channel-support/tests -v
```

`vendor/` holds the verifier deployed at api.dothat.quest. Every file except
`verifier/channel.py` is byte-identical to `route-v1/vendor/`; the hashes are
in `vendor-manifest.json`. The tests use synthetic keys and invented
transactions only.

## Replay a recorded run

Each run folder `channels/<channel>/runs/<challenge>/` contains the revealed
declaration, its RFC 3161 token, the public proof (for a base PASS), the
seller-signed channel artifact, the offline result and a Sigstore bundle over
its manifest.

```sh
openssl ts -verify -digest <commitment> -in declaration-timestamp.tsr -CAfile <system trust store>
openssl ts -reply -in declaration-timestamp.tsr -text
python channel-v1/verify_channel_release.py   --challenge-id <challenge> --channel <channel> --base-status PASS   --declaration declaration.json --proof proof.json --channel-artifact channel.json   --declaration-time <RFC 3161 time>   --not-before <verified attestation time of the channel layer>   --layer-sha256 <sha256 of channels/<channel>/freeze/manifest.json>   --output /new/path/verification.json
```

The record workflow takes `--not-before` only from `gh attestation verify` of
the layer commitment, and `--declaration-time` only from `openssl ts -verify`.
