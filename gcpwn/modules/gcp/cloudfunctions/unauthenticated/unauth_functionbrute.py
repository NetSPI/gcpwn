import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from gcpwn.core.utils.module_helpers import module_data_file, static_locations
from gcpwn.modules.gcp.cloudfunctions.utilities.helpers import check_anonymous_external


def _generate_base_urls(project: str, region: str | None) -> list[str]:
    all_regions = set(static_locations("cloudfunctions_v1")) | set(static_locations("cloudfunctions_v2"))
    regions = [region] if region else sorted(all_regions)
    return [f"https://{r}-{project}.cloudfunctions.net/" for r in regions]


def _load_permutations(wordlist_path: str | None) -> list[str]:
    if wordlist_path:
        with open(wordlist_path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    default = module_data_file(__file__, "..", "utilities", "data", "gcpfunctionsbrute_permutations.txt")
    with open(default, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _check(url: str, debug: bool) -> str | None:
    if check_anonymous_external(function_url=url, printout=False, debug=debug):
        return url
    return None


def run_module(user_args, session):
    project_id = session.project_id

    parser = argparse.ArgumentParser(
        description="Unauthenticated brute-force Cloud Function URLs",
        allow_abbrev=False,
    )
    parser.add_argument("-v", "--debug", action="store_true",
                        help="Verbose output during scanning")
    parser.add_argument("--region", default=None,
                        help="Target a single GCP region (default: all regions)")
    parser.add_argument("-w", "--wordlist", default=None,
                        help="Path to a custom wordlist file (one path suffix per line). "
                             "Default: built-in gcpfunctionsbrute_permutations.txt")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Number of concurrent worker threads (default: 10)")
    args = parser.parse_args(user_args)

    base_urls = _generate_base_urls(project_id, args.region)
    words = _load_permutations(args.wordlist)

    urls: list[str] = list(base_urls)
    for word in words:
        for base in base_urls:
            urls.append(base + word)

    print(f"\nGenerated {len(urls)} function URLs to probe.\n")

    hits: list[str] = []
    done = 0
    total = len(urls)
    start_time = time.time()
    cancelled = False

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(_check, url, args.debug): url for url in urls}
            try:
                for future in as_completed(futures):
                    done += 1
                    result = future.result()
                    if result:
                        hits.append(result)
                        print(f"[+] OPEN: {result}")
                    if done % 50 == 0 or done == total:
                        print(f"\r  [{done}/{total}] scanned, {len(hits)} open", end="", flush=True)
            except KeyboardInterrupt:
                cancelled = True
                print("\n[!] Ctrl+C — cancelling...")
                pool.shutdown(wait=False, cancel_futures=True)
    except KeyboardInterrupt:
        cancelled = True

    elapsed = timedelta(seconds=int(time.time() - start_time))
    d = datetime(1, 1, 1) + elapsed
    if d.day - 1 > 0:
        time_str = f"{d.day - 1}d {d.hour}h {d.minute}m {d.second}s"
    elif d.hour > 0:
        time_str = f"{d.hour}h {d.minute}m {d.second}s"
    elif d.minute > 0:
        time_str = f"{d.minute}m {d.second}s"
    else:
        time_str = f"{d.second}s"

    print(f"\n\nScanned {done}/{total} URLs in {time_str}. Open: {len(hits)}")
    for h in hits:
        print(f"  {h}")
    if cancelled:
        print("[!] Scan was interrupted.")
    return 1
