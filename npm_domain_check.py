import json
import sys
from collections import defaultdict
from typing import Any, Callable, Dict, Iterable, List, Set

import typer
from colorama import Fore, Style
from tqdm import tqdm

from domain_utils import DomainStatus, lookup_domain, whois_domain
from npm_utils import get_package_dependencies, get_package_emails

DOMAIN_WHITELIST = ["gmail.com"]


def bfs(init_queue: List[Any], next_func: Callable[[Any], Set]) -> Iterable[Any]:
    """ Simple breadth-first search """
    queue, visited = init_queue, set()
    while queue:
        vertex = queue.pop()
        if vertex not in visited:
            yield vertex
            visited.add(vertex)
            queue.extend(next_func(vertex) - visited)


def check_status(domain_status: str) -> DomainStatus:
    if any(
        domain_status.startswith(status)
        for status in [
            "ok",
            "active",
            "clientTransferProhibited",
            "clientUpdateProhibited",
        ]
    ):
        return DomainStatus.OK

    if any(
        domain_status.startswith(status)
        for status in ["redemptionPeriod", "pendingDelete",]
    ):
        return DomainStatus.EXPIRED

    return DomainStatus.UNKNOWN


def validate_domain(domain: str, resolve_first: bool) -> DomainStatus:
    if domain in DOMAIN_WHITELIST:
        return DomainStatus.OK

    if resolve_first and lookup_domain(domain):
        # If domain resolves - we assume it's not available for registration
        # (Speeds up the scan)
        return DomainStatus.OK

    # Check WHOIS records for the domain
    domain_record = whois_domain(domain)
    if not domain_record:
        return DomainStatus.NOT_FOUND
    if any(status.startswith("ok") for status in domain_record["domain_status"]):
        return DomainStatus.OK
    if domain_record["days_to_expire"] <= 0:
        return DomainStatus.EXPIRED

    return DomainStatus.UNKNOWN


def check_vulnerable_domains(domains: Dict[str, Set[str]], resolve_first: bool) -> bool:
    pbar = tqdm(domains, file=sys.stdout)
    found_vulnerable_domains = False
    for domain in pbar:
        pbar.set_description(f"Validating domain {domain}...")
        domain_status = validate_domain(domain, resolve_first)
        domain_status_str = ""
        if domain_status == DomainStatus.NOT_FOUND:
            domain_status_str = "not registered"
        elif domain_status == DomainStatus.EXPIRED:
            domain_status_str = "expired"

        if domain_status_str:
            found_vulnerable_domains = True
            affected_packages = ", ".join(domains[domain])
            print(Fore.RED + f"The domain {domain} is {domain_status_str}")
            print(Style.RESET_ALL, end="")
            print(f"Affected packages: {affected_packages}\n")

    return found_vulnerable_domains


def main(
    package_path: str, indirect_dependencies: bool = True, resolve_first: bool = True
):
    # Fetch the package name and direct dependencies
    with open(package_path) as f:
        try:
            package_json = json.load(f)
        except Exception:
            print(f'Cannot parse package JSON from "{package_path}"')
            return

    package_name = package_json.get("name", "")

    if not package_name:
        print(f"package.json config doesn't contain package name")
        return

    # Fetch the user's direct packages
    direct_packages = list(package_json.get("dependencies", {}).keys())
    print(f'Package "{package_name}" depends on {len(direct_packages)} direct packages')

    # Get domain names for all direct dependencies
    # Optionally, include indirect dependencies
    next_func = get_package_dependencies if indirect_dependencies else lambda x: set()
    domains = defaultdict(set)
    pbar = tqdm(bfs(list(direct_packages), next_func=next_func), file=sys.stdout)
    for pkg_name in pbar:
        pbar.set_description(f'Fetching domains for package "{pkg_name}"...')
        for email in get_package_emails(pkg_name):
            _, _, domain = email.partition("@")
            if domain:
                domains[domain].add(pkg_name)
    print(f"Found {len(domains)} domains")

    # Check if any domain is in a vulnerable state
    found_vulnerable_domains = check_vulnerable_domains(domains, resolve_first)
    if not found_vulnerable_domains:
        print(Fore.GREEN + f'All domains for package "{package_name}" are safe')
        print(Style.RESET_ALL)


if __name__ == "__main__":
    typer.run(main)
