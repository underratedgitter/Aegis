#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from urllib.request import urlopen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout-url", default="http://localhost:8080")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    for _ in range(args.count):
        url = f"{args.checkout_url.rstrip('/')}/api/checkout"
        with urlopen(url, timeout=5) as response:
            print(response.status, json.loads(response.read()))
        time.sleep(0.15)


if __name__ == "__main__":
    main()
