#!/usr/bin/env python3
"""
Decode JWT header/payload data and optionally print key IDs from a JWKS file.

This is a debugging helper only. It does not verify the JWT signature.
"""

import argparse
import base64
import json
import sys


def b64url_decode(part):
    padding = "=" * ((4 - len(part) % 4) % 4)
    return base64.urlsafe_b64decode(part + padding)


def print_json(label, value):
    print(f"{label}:")
    print(json.dumps(value, indent=2, sort_keys=True))


def decode_token(token):
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("token does not have JWT header.payload segments")

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def main():
    parser = argparse.ArgumentParser(
        description="Inspect an nginx-xrootd test JWT and/or JWKS file"
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="JWT to inspect, or '-' to read from stdin",
    )
    parser.add_argument(
        "--jwks",
        help="JWKS file whose key IDs should be printed",
    )
    args = parser.parse_args()

    if args.token:
        _print_token(args.token)

    if args.jwks:
        _print_jwks(args.jwks, leading_blank=bool(args.token))


def _print_token(argument):
    token = sys.stdin.read().strip() if argument == "-" else argument
    header, payload = decode_token(token)
    print_json("Header", header)
    print()
    print_json("Payload", payload)


def _print_jwks(path, *, leading_blank):
    if leading_blank:
        print()
    with open(path, "r", encoding="utf-8") as handle:
        jwks = json.load(handle)
    print("JWKS key IDs:")
    for key in jwks.get("keys", []):
        print(f"  {key.get('kid', '<missing kid>')}")


if __name__ == "__main__":
    main()
