#!/usr/bin/env python3
"""
Baskerville /eq402 end-to-end payment test.

Visits the dedicated /eq402 test page (always behind the paywall),
pays, verifies, and displays the congratulations page.

Usage:
    # Manual mode — pay in MetaMask yourself, paste tx_hash:
    python test_pay.py --manual --site http://localhost:8080

    # Stub mode (demo_ tx_hash, no real blockchain tx):
    python test_pay.py --stub --site http://localhost:8080

    # Automatic payment via private key:
    PRIVATE_KEY=0x... python test_pay.py --site http://localhost:8080

    # Explicit private key + custom RPC:
    python test_pay.py --site http://localhost:8080 --private-key 0x... --rpc-url https://...
"""

import argparse
import json
import os
import sys
import time
from decimal import Decimal

import requests

# Minimal ERC-20 ABI (only transfer)
ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
]

AMOY_RPC = "https://rpc-amoy.polygon.technology"


def info(msg):
    print(f"  {msg}")


def header(msg):
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def step(n, msg):
    print(f"\n[{n}] {msg}")


def send_real_payment(private_key, rpc_url, wallet, amount, asset_type, token_contract, token_decimals):
    """Send a real payment on-chain via web3.py. Returns tx_hash hex string."""
    try:
        from web3 import Web3
    except ImportError:
        print("Error: web3 package required. Run: pip install web3")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"Error: Cannot connect to RPC at {rpc_url}")
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    sender = account.address
    info(f"Wallet address: {sender}")
    info(f"Native balance: {w3.from_wei(w3.eth.get_balance(sender), 'ether')}")

    if asset_type == "native":
        value_wei = w3.to_wei(Decimal(amount), "ether")
        tx = {
            "to": wallet,
            "value": value_wei,
            "gas": 21000,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(sender),
            "chainId": w3.eth.chain_id,
        }
    else:
        contract_addr = Web3.to_checksum_address(token_contract)
        usdc = w3.eth.contract(address=contract_addr, abi=ERC20_ABI)
        amount_smallest = int(Decimal(amount) * (10 ** token_decimals))
        tx = usdc.functions.transfer(
            Web3.to_checksum_address(wallet),
            amount_smallest,
        ).build_transaction({
            "from": sender,
            "gas": 100000,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(sender),
            "chainId": w3.eth.chain_id,
        })

    info(f"Sending {amount} {asset_type} to {wallet}...")
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    info(f"tx_hash: {tx_hash_hex}")

    info("Waiting for transaction receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    info(f"Block: {receipt['blockNumber']}, Status: {receipt['status']}")

    if receipt["status"] != 1:
        print("Error: Transaction reverted on-chain")
        return None

    return tx_hash_hex


def main():
    parser = argparse.ArgumentParser(description="Baskerville /eq402 end-to-end payment test")
    parser.add_argument("--site", required=True, help="WordPress site URL (e.g. http://localhost:8080)")
    parser.add_argument("--manual", action="store_true", help="Manual mode: pay in MetaMask, paste tx_hash")
    parser.add_argument("--private-key", default=None, help="Wallet private key (or PRIVATE_KEY env var)")
    parser.add_argument("--rpc-url", default=AMOY_RPC, help=f"RPC endpoint (default: Amoy testnet)")
    parser.add_argument("--stub", action="store_true", help="Use demo_ tx_hash (no real blockchain payment)")
    args = parser.parse_args()

    private_key = args.private_key or os.environ.get("PRIVATE_KEY", "")

    # Determine mode
    if args.manual:
        mode = "manual"
    elif args.stub:
        mode = "stub"
    elif private_key:
        mode = "live"
    else:
        print("Error: Use --manual, --stub, or provide --private-key / PRIVATE_KEY env var.")
        sys.exit(1)

    site = args.site.rstrip("/")
    eq402_url = f"{site}/eq402"

    header("Baskerville Pay-Per-Crawl Test")
    info(f"Target: {eq402_url}")
    info(f"Mode:   {mode}")

    # ── Step 1: GET /eq402 → expect 402 ──────────────────────
    step(1, f"GET {eq402_url}")
    resp = requests.get(eq402_url, allow_redirects=True)
    info(f"Status: {resp.status_code}")

    # Use the final URL after redirects (http→https, www, trailing slash, etc.)
    # This ensures Bearer header isn't stripped on redirect in step 4.
    if resp.url != eq402_url:
        eq402_url = resp.url
        info(f"Redirected to: {eq402_url}")

    if resp.status_code != 402:
        print(f"\nExpected 402, got {resp.status_code}.")
        if resp.status_code == 503:
            print("The /eq402 page says paywall is not enabled/enforced.")
            print("Ensure pay_enabled=true and pay_mode=enforce in Baskerville settings.")
        print(f"Body: {resp.text[:500]}")
        sys.exit(1)

    try:
        challenge = resp.json()
    except json.JSONDecodeError:
        print("Error: 402 response is not valid JSON")
        print(f"Body: {resp.text[:500]}")
        sys.exit(1)

    req_id         = challenge.get("req_id", "")
    amount         = challenge.get("amount", "0")
    wallet         = challenge.get("wallet", "")
    currency       = challenge.get("currency", "")
    network        = challenge.get("network", "")
    asset_type     = challenge.get("asset_type", "")
    token_contract = challenge.get("token_contract", "")
    token_decimals = challenge.get("token_decimals", 6)
    proof_endpoint = challenge.get("proof_endpoint", "")

    info(f"Challenge received:")
    info(f"  req_id:   {req_id}")
    info(f"  amount:   {amount} {currency}")
    info(f"  network:  {network}")
    info(f"  wallet:   {wallet}")
    info(f"  asset:    {asset_type}")
    if token_contract:
        info(f"  token:    {token_contract}")
    info(f"  verify:   {proof_endpoint}")

    # ── Step 2: Pay ───────────────────────────────────────────
    tx_hash = None

    if mode == "manual":
        step(2, "Manual payment")
        print()
        print("  Send the following payment in MetaMask:")
        print(f"    To:       {wallet}")
        print(f"    Amount:   {amount} {currency}")
        print(f"    Network:  {network}")
        if asset_type == "erc20" and token_contract:
            print(f"    Token:    {token_contract}")
        print()
        print("  After the transaction confirms, paste the tx hash below.")
        print()
        tx_hash = input("  tx_hash: ").strip()
        if not tx_hash:
            print("Error: No tx_hash provided.")
            sys.exit(1)
        info(f"Using tx_hash: {tx_hash}")

    elif mode == "stub":
        step(2, "Generating demo tx_hash (stub mode)")
        tx_hash = f"demo_{int(time.time())}_{req_id[:8]}"
        info(f"tx_hash: {tx_hash}")

    elif mode == "live":
        step(2, f"Sending {amount} {currency} on {network}")
        tx_hash = send_real_payment(
            private_key=private_key,
            rpc_url=args.rpc_url,
            wallet=wallet,
            amount=amount,
            asset_type=asset_type,
            token_contract=token_contract,
            token_decimals=token_decimals,
        )
        if not tx_hash:
            print("Error: Transaction failed")
            sys.exit(1)

    # ── Step 3: Verify payment ────────────────────────────────
    verify_url = proof_endpoint
    if not verify_url.startswith("http"):
        verify_url = f"{site}{verify_url}"

    while True:
        step(3, "Verifying payment...")
        info(f"POST {verify_url}")
        verify_resp = requests.post(
            verify_url,
            json={"req_id": req_id, "tx_hash": tx_hash},
            headers={"Content-Type": "application/json"},
        )
        info(f"Status: {verify_resp.status_code}")

        # Handle pending (unconfirmed) — auto-retry up to 60s
        if verify_resp.status_code == 202:
            info("Payment pending (unconfirmed). Waiting for confirmations...")
            for attempt in range(1, 13):
                time.sleep(5)
                verify_resp = requests.post(
                    verify_url,
                    json={"req_id": req_id, "tx_hash": tx_hash},
                    headers={"Content-Type": "application/json"},
                )
                info(f"Retry {attempt}: status {verify_resp.status_code}")
                if verify_resp.status_code != 202:
                    break

        if verify_resp.status_code == 200:
            break

        # Verification failed — show error
        try:
            err = verify_resp.json()
            err_code = err.get("code", "unknown")
        except Exception:
            err_code = "unknown"

        err_detail = err.get("detail", "") if isinstance(err, dict) else ""
        print(f"\n  Verification failed: {verify_resp.status_code} ({err_code})")
        if err_detail:
            print(f"  Detail: {err_detail}")

        if err_code == "invalid_tx":
            print("  The tx_hash was rejected. Possible causes:")
            print("    - pay_verifier_type is 'stub' (only accepts demo_ hashes)")
            print("    - Transaction not found on-chain or reverted")
            print("    - Wrong tx_hash format")
        elif err_code == "provider_error":
            print("  The server could not reach the blockchain RPC.")
            print("  Check pay_provider / pay_api_key in Baskerville settings,")
            print("  or the server may not have outbound HTTPS access.")

        if mode == "manual":
            print()
            retry = input("  Try another tx_hash? [Y/n]: ").strip().lower()
            if retry in ("n", "no"):
                sys.exit(1)
            tx_hash = input("  tx_hash: ").strip()
            if not tx_hash:
                print("Error: No tx_hash provided.")
                sys.exit(1)
            info(f"Using tx_hash: {tx_hash}")
            continue
        else:
            print(f"  Response: {verify_resp.text[:500]}")
            sys.exit(1)

    verify_data = verify_resp.json()
    grant      = verify_data.get("grant", "")
    grant_url  = verify_data.get("grant_url", "")
    expires_at = verify_data.get("expires_at", "")

    info(f"Grant received: {grant[:40]}...")
    info(f"Expires at:     {expires_at}")
    if grant_url:
        info(f"Grant URL:      {grant_url[:80]}...")

    # ── Step 4: GET /eq402 with grant → expect 200 ───────────
    # Try grant_url first (CDN-friendly: grant in query param bypasses edge cache),
    # fall back to Authorization: Bearer header.
    if grant_url:
        step(4, f"GET grant_url (CDN-friendly query param)")
        info(f"URL: {grant_url[:100]}...")
        content_resp = requests.get(grant_url, allow_redirects=True)
        info(f"Status: {content_resp.status_code}")

        if content_resp.status_code != 200:
            info("grant_url failed, falling back to Authorization: Bearer header...")
            content_resp = requests.get(
                eq402_url,
                headers={"Authorization": f"Bearer {grant}"},
                allow_redirects=True,
            )
            info(f"Status (Bearer): {content_resp.status_code}")
    else:
        step(4, f"GET {eq402_url} with Bearer grant")
        content_resp = requests.get(
            eq402_url,
            headers={"Authorization": f"Bearer {grant}"},
            allow_redirects=True,
        )
        info(f"Status: {content_resp.status_code}")

    if content_resp.status_code == 200:
        print(f"\n{content_resp.text}")
        header("SUCCESS")
    else:
        print(f"\nFAILED: Expected 200, got {content_resp.status_code}")
        # Show debug headers from server
        for h in ("X-Eq402-Debug-Canonical", "X-Eq402-Debug-Has-Auth", "X-Eq402-Debug-Token-Prefix"):
            if h in content_resp.headers:
                info(f"{h}: {content_resp.headers[h]}")
        info(f"Final URL: {content_resp.url}")
        print(f"Body: {content_resp.text[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
