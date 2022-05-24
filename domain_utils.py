from datetime import datetime
from enum import Enum
from typing import Optional

import dns
import dns.resolver
from whois import whois


class DomainStatus(Enum):
    OK = 1
    NOT_FOUND = 2
    EXPIRED = 3
    UNKNOWN = 4


def whois_domain(domain: str) -> Optional[dict]:
    now = datetime.now()

    try:
        whois_data = whois(domain)
    except Exception as exc:
        print(f"Can't parse {domain}: {str(exc)}")
        return None
    if not whois_data:
        return None
    if any(
        _ in whois_data.text.lower()
        for _ in ["not found", "no data found", "available for registration"]
    ):
        return None
    if isinstance(whois_data.expiration_date, list):
        expiration_date = whois_data.expiration_date[0]
    else:
        expiration_date = whois_data.expiration_date
    if not expiration_date:
        return None
    domain_expiration_date = (
        str(expiration_date.day)
        + "/"
        + str(expiration_date.month)
        + "/"
        + str(expiration_date.year)
    )
    timedelta = expiration_date - now
    return {
        "days_to_expire": timedelta.days,
        "domain_expiration_date": domain_expiration_date,
        "domain_registrar": whois_data.registrar,
        "domain_status": whois_data.status,
    }


def lookup_domain(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except dns.exception.DNSException:
        try:
            dns.resolver.resolve(domain, "MX")
            return True
        except dns.exception.DNSException:
            try:
                dns.resolver.resolve(domain, "NX")
                return True
            except dns.exception.DNSException:
                return False
