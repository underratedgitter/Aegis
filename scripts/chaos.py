#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
from urllib.request import Request, urlopen


def inject(base_url: str, service: str, fault: str, duration: float, intensity: float) -> None:
    request = Request(
        f"{base_url.rstrip('/')}/api/chaos",
        data=json.dumps(
            {
                "service": service,
                "fault": fault,
                "duration_seconds": duration,
                "intensity": intensity,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        print(json.loads(response.read()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject bounded failures into the Aegis demo.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--service", choices=("checkout", "inventory"), default="inventory")
    parser.add_argument(
        "--fault", choices=("latency", "errors", "dependency", "cpu"), default="dependency"
    )
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--intensity", type=float, default=1)
    parser.add_argument(
        "--random", action="store_true", help="keep injecting random bounded incidents"
    )
    args = parser.parse_args()
    while True:
        service = random.choice(("checkout", "inventory")) if args.random else args.service
        fault = (
            random.choice(("latency", "errors", "dependency", "cpu")) if args.random else args.fault
        )
        inject(args.base_url, service, fault, args.duration, args.intensity)
        if not args.random:
            return
        time.sleep(args.duration + random.uniform(5, 20))


if __name__ == "__main__":
    main()
