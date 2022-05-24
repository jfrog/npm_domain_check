import logging
from datetime import datetime
from functools import lru_cache
from typing import List, Optional, Set, Union

import requests


def str_to_date(date_str: Union[dict, str]) -> datetime:
    if isinstance(date_str, dict):
        date_str = date_str["time"]
    return datetime.strptime(date_str[:-5], "%Y-%m-%dT%H:%M:%S")


def get_user_data(user_name: str, page: int) -> dict:
    headers = {"authority": "www.npmjs.com", "accept": "*/*", "x-spiferack": "1"}
    params = {"page": str(page)}

    response = requests.get(
        f"https://www.npmjs.com/~{user_name}", params=params, headers=headers
    )
    if not response:
        logging.warning(
            "Can't fetch page %s of %s (status code: %d)",
            page,
            user_name,
            response.status_code,
        )
        return {}

    return response.json()


@lru_cache()
def get_package_details(package_name: str) -> dict:
    response = requests.get(f"https://registry.npmjs.org/{package_name}")
    if not response:
        print(f"Can't get data of {package_name} ({response.status_code})")
        return {}

    return response.json()


def get_latest_version_name(package_details: dict) -> Optional[str]:
    times = [
        (version_name, version_mod)
        for version_name, version_mod in package_details.get("time", {}).items()
        if version_name not in ["created", "modified", "unpublished"]
    ]
    sorted_times = sorted(times, key=lambda x: str_to_date(x[1]))
    if not sorted_times:
        return None
    return sorted_times[-1][0]


def get_package_dependencies(package_name: str) -> Set[str]:
    res = set([])
    package_data = get_package_details(package_name)
    version_name = get_latest_version_name(package_data)
    if not version_name:
        return res
    version_data = package_data.get("versions", {}).get(version_name, {})
    if not version_data:
        return res
    res.update(version_data.get("dependencies", {}).keys())
    return res


def get_package_emails(package_name: str) -> List[str]:
    return [
        maintainer["email"]
        for maintainer in get_package_details(package_name).get("maintainers")
        if "email" in maintainer
    ]
