#!/usr/bin/env python3
"""
Baskerville Pay-Per-Crawl demo client.

Demonstrates the full 402 -> pay -> verify -> access cycle.

Usage:
    # Stub mode (no real transaction, uses demo_ tx_hash):
    python pay_crawler.py --stub --site http://localhost:8080 --path /sample-page/

    # Live mode on Polygon Amoy testnet:
    PRIVATE_KEY=0x... python pay_crawler.py --live --site http://localhost:8080 --path /sample-page/

    # Verbose output:
    python pay_crawler.py --stub --site http://localhost:8080 --path /sample-page/ --verbose
"""

import argparse
import json
import sys
import time
from decimal import Decimal

import requests

# Minimal ERC-20 ABI (only transfer + decimals)
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
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]

# Polygon Amoy testnet USDC (Circle test token)
AMOY_USDC = "0x41E94Eb71898E8A20f83f5e9A23dA396be8E5F93"
AMOY_RPC = "https://rpc-amoy.polygon.technology"

AI_BOT_UA = "GPTBot/1.0 (+https://openai.com/gptbot)"


def log(msg, verbose=True):
    if verbose:
        print(f"  -> {msg}")


def step(n, msg):
    print(f"\n[Step {n}] {msg}")


def main():
    parser = argparse.ArgumentParser(description="Baskerville Pay-Per-Crawl demo client")
    parser.add_argument("--site", required=True, help="WordPress site URL (e.g. http://localhost:8080)")
    parser.add_argument("--path", default="/sample-page/", help="Path to request (default: /sample-page/)")
    parser.add_argument("--stub", action="store_true", help="Use stub verifier (demo_ tx_hash, no real tx)")
    parser.add_argument("--live", action="store_true", help="Send real tx on Amoy testnet")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--rpc-url", default=AMOY_RPC, help="RPC URL for live mode")
    parser.add_argument("--private-key", default=None, help="Private key (or use PRIVATE_KEY env var)")
    args = parser.parse_args()

    if not args.stub and not args.live:
        args.stub = True  # Default to stub

    site = args.site.rstrip("/")
    url = f"{site}{args.path}"
    verbose = args.verbose

    # ── Step 1: GET page with AI bot User-Agent → expect 402 ──
    step(1, f"GET {url} with AI bot User-Agent")
    resp = requests.get(url, headers={"User-Agent": AI_BOT_UA}, allow_redirects=True)
    log(f"Status: {resp.status_code}", verbose)

    if resp.status_code != 402:
        print(f"\nExpected 402, got {resp.status_code}.")
        if resp.status_code == 200:
            print("Page served without paywall. Check that pay_enabled=true, pay_mode=enforce,")
            print("and ai_score threshold is met for this User-Agent.")
        if verbose:
            print(f"Headers: {dict(resp.headers)}")
            print(f"Body (first 500 chars): {resp.text[:500]}")
        sys.exit(1)

    try:
        challenge = resp.json()
    except json.JSONDecodeError:
        print("Error: 402 response is not valid JSON")
        print(f"Body: {resp.text[:500]}")
        sys.exit(1)

    req_id = challenge.get("req_id", "")
    amount = challenge.get("amount", "0")
    wallet = challenge.get("wallet", "")
    currency = challenge.get("currency", "")
    network = challenge.get("network", "")
    asset_type = challenge.get("asset_type", "")
    token_contract = challenge.get("token_contract", "")
    proof_endpoint = challenge.get("proof_endpoint", "")

    print(f"  Challenge received:")
    print(f"    req_id:         {req_id}")
    print(f"    amount:         {amount} {currency}")
    print(f"    network:        {network}")
    print(f"    wallet:         {wallet}")
    print(f"    asset_type:     {asset_type}")
    if token_contract:
        print(f"    token_contract: {token_contract}")
    print(f"    proof_endpoint: {proof_endpoint}")

    # ── Step 2: Pay ──
    tx_hash = None

    if args.stub:
        step(2, "Using stub verifier (demo_ tx_hash)")
        tx_hash = f"demo_{int(time.time())}_{req_id[:8]}"
        log(f"tx_hash: {tx_hash}", verbose)

    elif args.live:
        step(2, "Sending real transaction on testnet")
        tx_hash = send_real_payment(
            args=args,
            wallet=wallet,
            amount=amount,
            asset_type=asset_type,
            token_contract=token_contract,
            token_decimals=challenge.get("token_decimals", 6),
            verbose=verbose,
        )
        if not tx_hash:
            print("Error: Transaction failed")
            sys.exit(1)

    # ── Step 3: Verify payment ──
    verify_url = proof_endpoint
    if not verify_url.startswith("http"):
        verify_url = f"{site}{verify_url}"

    step(3, f"POST {verify_url}")
    verify_resp = requests.post(
        verify_url,
        json={"req_id": req_id, "tx_hash": tx_hash},
        headers={"Content-Type": "application/json"},
    )
    log(f"Status: {verify_resp.status_code}", verbose)

    if verify_resp.status_code == 202:
        print("  Payment pending (unconfirmed). Retrying in 5 seconds...")
        for attempt in range(1, 13):
            time.sleep(5)
            verify_resp = requests.post(
                verify_url,
                json={"req_id": req_id, "tx_hash": tx_hash},
                headers={"Content-Type": "application/json"},
            )
            log(f"Retry {attempt}: status {verify_resp.status_code}", verbose)
            if verify_resp.status_code != 202:
                break

    if verify_resp.status_code != 200:
        print(f"\nVerification failed: {verify_resp.status_code}")
        print(f"Response: {verify_resp.text[:500]}")
        sys.exit(1)

    verify_data = verify_resp.json()
    grant = verify_data.get("grant", "")
    grant_url = verify_data.get("grant_url", "")
    expires_at = verify_data.get("expires_at", "")

    print(f"  Grant received:")
    print(f"    grant:      {grant[:40]}...")
    print(f"    expires_at: {expires_at}")
    if grant_url:
        print(f"    grant_url:  {grant_url[:80]}...")

    # ── Step 4: GET page with grant → expect 200 ──
    # Prefer grant_url (query param) for CDN compatibility, fall back to Bearer header
    if grant_url:
        step(4, f"GET grant_url (CDN-friendly)")
        content_resp = requests.get(
            grant_url,
            headers={"User-Agent": AI_BOT_UA},
            allow_redirects=True,
        )
        log(f"Status: {content_resp.status_code}", verbose)

        if content_resp.status_code != 200:
            log("grant_url failed, falling back to Bearer header...", verbose)
            content_resp = requests.get(
                url,
                headers={
                    "User-Agent": AI_BOT_UA,
                    "Authorization": f"Bearer {grant}",
                },
                allow_redirects=True,
            )
            log(f"Status (Bearer): {content_resp.status_code}", verbose)
    else:
        step(4, f"GET {url} with Bearer grant")
        content_resp = requests.get(
            url,
            headers={
                "User-Agent": AI_BOT_UA,
                "Authorization": f"Bearer {grant}",
            },
            allow_redirects=True,
        )
        log(f"Status: {content_resp.status_code}", verbose)

    if content_resp.status_code == 200:
        print("\n  SUCCESS! Content served with valid grant.")
        if verbose:
            body = content_resp.text
            print(f"\n  Content (first 300 chars):\n  {body[:300]}")
    else:
        print(f"\n  FAILED: Expected 200, got {content_resp.status_code}")
        if verbose:
            print(f"  Headers: {dict(content_resp.headers)}")
            print(f"  Body: {content_resp.text[:500]}")
        sys.exit(1)


def send_real_payment(args, wallet, amount, asset_type, token_contract, token_decimals, verbose):
    """Send a real payment on testnet via web3.py."""
    try:
        from web3 import Web3
    except ImportError:
        print("Error: web3 package required for live mode. Run: pip install web3")
        sys.exit(1)

    import os

    private_key = args.private_key or os.environ.get("PRIVATE_KEY", "")
    if not private_key:
        print("Error: --private-key or PRIVATE_KEY env var required for live mode")
        sys.exit(1)

    rpc_url = args.rpc_url
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        print(f"Error: Cannot connect to RPC at {rpc_url}")
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    sender = account.address
    log(f"Sender address: {sender}", verbose)
    log(f"Balance: {w3.from_wei(w3.eth.get_balance(sender), 'ether')} native", verbose)

    if asset_type == "native":
        # Send native currency
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
        # Send ERC-20 token
        contract_addr = Web3.to_checksum_address(token_contract)
        usdc = w3.eth.contract(address=contract_addr, abi=ERC20_ABI)
        amount_smallest = int(Decimal(amount) * (10 ** token_decimals))

        tx = usdc.functions.transfer(
            Web3.to_checksum_address(wallet),
            amount_smallest,
        ).build_transaction(
            {
                "from": sender,
                "gas": 100000,
                "gasPrice": w3.eth.gas_price,
                "nonce": w3.eth.get_transaction_count(sender),
                "chainId": w3.eth.chain_id,
            }
        )

    log("Signing and sending transaction...", verbose)
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    log(f"tx_hash: {tx_hash_hex}", verbose)

    log("Waiting for transaction receipt...", verbose)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    log(f"Block: {receipt['blockNumber']}, Status: {receipt['status']}", verbose)

    if receipt["status"] != 1:
        print("Error: Transaction reverted on-chain")
        return None

    return tx_hash_hex


if __name__ == "__main__":
    main()
