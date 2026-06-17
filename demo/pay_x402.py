#!/usr/bin/env python3
"""
X402 V2 payment script for Baskerville paywall.
Signs EIP-3009 TransferWithAuthorization and pays USDC via Coinbase facilitator.

Usage:
  export PRIVATE_KEY=0x...
  python3 pay_x402.py https://thephotoschool.ca/eq402

Requirements:
  pip install eth-account requests
"""

import os
import sys
import json
import base64
import secrets
import time
import requests
from eth_account import Account
from eth_account.messages import encode_typed_data


# ── helpers ──────────────────────────────────────────────────────────────────

def b64_decode_header(value: str) -> dict:
    """Decode a standard base64-encoded JSON header value."""
    # Add padding if needed
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return json.loads(base64.b64decode(value))


def b64_encode_payload(obj: dict) -> str:
    """Base64-encode a dict as JSON (standard base64, not url-safe)."""
    return base64.b64encode(json.dumps(obj).encode()).decode()


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://thephotoschool.ca/eq402"

    private_key = os.environ.get("PRIVATE_KEY")
    if not private_key:
        print("Error: set PRIVATE_KEY environment variable")
        print("  export PRIVATE_KEY=0x<your-private-key>")
        sys.exit(1)

    account = Account.from_key(private_key)
    print(f"Wallet:  {account.address}")
    print(f"URL:     {url}")

    # ── Step 1: GET → 402 ────────────────────────────────────────────────────
    print("\n[1] Fetching resource...")
    resp = requests.get(url, allow_redirects=False)
    print(f"    Status: {resp.status_code}")

    if resp.status_code != 402:
        print(f"    Expected 402, got {resp.status_code}")
        sys.exit(1)

    pr_header = resp.headers.get("payment-required") or resp.headers.get("PAYMENT-REQUIRED")
    if not pr_header:
        print("    No PAYMENT-REQUIRED header found")
        sys.exit(1)

    pr = b64_decode_header(pr_header)
    requirement = pr["accepts"][0]

    network      = requirement["network"]            # eip155:84532
    asset        = requirement["asset"]              # USDC contract address
    amount       = int(requirement["amount"])        # atomic units
    pay_to       = requirement["payTo"]
    chain_id     = int(network.split(":")[1])
    usdc_name    = requirement.get("extra", {}).get("name", "USD Coin")
    usdc_version = requirement.get("extra", {}).get("version", "2")

    print(f"\n    Payment details:")
    print(f"      Network:  {network} (chainId={chain_id})")
    print(f"      Asset:    {asset}")
    print(f"      Amount:   {amount} ({amount / 1e6:.4f} USDC)")
    print(f"      Pay to:   {pay_to}")

    # ── Step 2: Sign EIP-3009 TransferWithAuthorization ──────────────────────
    print("\n[2] Signing EIP-3009 authorization...")

    nonce        = "0x" + secrets.token_hex(32)
    valid_after  = 0
    valid_before = int(time.time()) + 3600  # 1 hour validity

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name",              "type": "string"},
                {"name": "version",           "type": "string"},
                {"name": "chainId",           "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from",        "type": "address"},
                {"name": "to",          "type": "address"},
                {"name": "value",       "type": "uint256"},
                {"name": "validAfter",  "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce",       "type": "bytes32"},
            ],
        },
        "domain": {
            "name":              usdc_name,
            "version":           usdc_version,
            "chainId":           chain_id,
            "verifyingContract": asset,
        },
        "primaryType": "TransferWithAuthorization",
        "message": {
            "from":        account.address,
            "to":          pay_to,
            "value":       amount,
            "validAfter":  valid_after,
            "validBefore": valid_before,
            "nonce":       nonce,
        },
    }

    signable = encode_typed_data(full_message=typed_data)
    signed   = account.sign_message(signable)
    signature = "0x" + signed.signature.hex()

    print(f"    Nonce:     {nonce[:20]}...")
    print(f"    Valid until: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(valid_before))}")
    print(f"    Signature: {signature[:20]}...")

    # ── Step 3: Build X402 payment payload ───────────────────────────────────
    print("\n[3] Building X402 payment payload...")

    payment_payload = {
        "x402Version": 2,
        "resource":    pr["resource"],
        "accepted":    requirement,
        "payload": {
            "signature": signature,
            "authorization": {
                "from":        account.address,
                "to":          pay_to,
                "value":       str(amount),
                "validAfter":  str(valid_after),
                "validBefore": str(valid_before),
                "nonce":       nonce,
            },
        },
    }

    payment_sig_b64 = b64_encode_payload(payment_payload)
    print(f"    Payload size: {len(payment_sig_b64)} bytes (base64)")

    # ── Step 4: Retry with PAYMENT-SIGNATURE ─────────────────────────────────
    print(f"\n[4] Sending payment to {url}...")
    resp2 = requests.get(url, headers={"PAYMENT-SIGNATURE": payment_sig_b64}, allow_redirects=False)
    print(f"    Status: {resp2.status_code}")

    if resp2.status_code == 200:
        print("\n✓ Payment accepted! Access granted.\n")

        x_resp_header = resp2.headers.get("x-payment-response")
        if x_resp_header:
            try:
                x_resp = b64_decode_header(x_resp_header)
                print(f"  Transaction: {x_resp.get('transaction', 'n/a')}")
                print(f"  Network:     {x_resp.get('network', 'n/a')}")
                print(f"  Payer:       {x_resp.get('payer', 'n/a')}")
            except Exception:
                pass

        # Grant arrives as header (after fix) or cookie fallback
        grant = resp2.headers.get("baskerville-grant") or resp2.cookies.get("baskerville_grant")
        if grant:
            print(f"\n  BV1 Grant (save for subsequent requests):")
            print(f"  {grant}")

            # ── Step 5: Retry with grant token (no payment) ──────────────────
            print(f"\n[5] Testing grant reuse (no payment)...")
            resp3 = requests.get(url, headers={"Authorization": f"Bearer {grant}"}, allow_redirects=False)
            print(f"    Status: {resp3.status_code}")
            if resp3.status_code == 200:
                print("    ✓ Grant accepted — access without payment!")
            elif resp3.status_code == 402:
                print("    ✗ Grant rejected — got 402 again")
            else:
                print(f"    ? Unexpected: {resp3.status_code}")

            # ── Step 6: Double-spend attempt (replay same PAYMENT-SIGNATURE) ──
            print(f"\n[6] Testing double-spend (replay same PAYMENT-SIGNATURE)...")
            resp4 = requests.get(url, headers={"PAYMENT-SIGNATURE": payment_sig_b64}, allow_redirects=False)
            print(f"    Status: {resp4.status_code}")
            if resp4.status_code == 402:
                print("    ✓ Double-spend blocked — got 402!")
            elif resp4.status_code == 200:
                print("    ✗ Double-spend succeeded — VULNERABILITY!")
            else:
                print(f"    ? Unexpected: {resp4.status_code}")
        else:
            print("\n  ⚠ No Baskerville-Grant header in response")
            print(f"  Response headers: {dict(resp2.headers)}")

    elif resp2.status_code == 402:
        print("\n✗ Payment rejected — still 402")
        pr2_header = resp2.headers.get("payment-required")
        if pr2_header:
            try:
                pr2 = b64_decode_header(pr2_header)
                print(json.dumps(pr2, indent=2))
            except Exception:
                print(resp2.text[:500])
    else:
        print(f"\n✗ Unexpected status: {resp2.status_code}")
        print(resp2.text[:500])


if __name__ == "__main__":
    main()
