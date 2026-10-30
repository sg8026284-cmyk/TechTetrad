"""Embedded vulnerability advisory database for offline and reproducible dependency audits."""

from typing import List, Optional
from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet
from ..models import AdvisoryReference, VulnerabilitySeverity


# Pre-seeded advisory database modeled after OSV / GHSA / CVE records
EMBEDDED_ADVISORIES: List[dict] = [
    {
        "advisory_id": "GHSA-j8r2-6x86-q33q",
        "aliases": ["CVE-2018-18074"],
        "package": "requests",
        "ecosystem": "PyPI",
        "affected_spec": "<2.20.0",
        "fixed_version": "2.20.0",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 7.5,
        "summary": "Requests sends HTTP Basic Authentication credentials on redirect to HTTPS host on same domain name.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-18074", "https://github.com/psf/requests/pull/4790"]
    },
    {
        "advisory_id": "GHSA-nh37-g6wf-r5q8",
        "aliases": ["CVE-2019-11324"],
        "package": "urllib3",
        "ecosystem": "PyPI",
        "affected_spec": "<1.24.2",
        "fixed_version": "1.24.2",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 7.5,
        "summary": "Urllib3 SSL verification bypass when using custom SSLContext.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11324"]
    },
    {
        "advisory_id": "GHSA-w4w3-hf69-crrf",
        "aliases": ["CVE-2018-1000656"],
        "package": "flask",
        "ecosystem": "PyPI",
        "affected_spec": "<0.12.3",
        "fixed_version": "0.12.3",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 7.5,
        "summary": "Flask unexpected memory consumption and denial of service via large JSON decoding payloads.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000656"]
    },
    {
        "advisory_id": "GHSA-qgmg-xpp4-765h",
        "aliases": ["CVE-2019-10906"],
        "package": "jinja2",
        "ecosystem": "PyPI",
        "affected_spec": "<2.10.1",
        "fixed_version": "2.10.1",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 8.1,
        "summary": "Jinja2 Sandbox Escape through string format expressions.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10906"]
    },
    {
        "advisory_id": "GHSA-5627-xx2w-4xgh",
        "aliases": ["CVE-2020-14343"],
        "package": "pyyaml",
        "ecosystem": "PyPI",
        "affected_spec": "<5.4",
        "fixed_version": "5.4",
        "severity": VulnerabilitySeverity.CRITICAL,
        "cvss_score": 9.8,
        "summary": "PyYAML arbitrary code execution via FullLoader and load() method.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"]
    },
    {
        "advisory_id": "GHSA-v6rh-hp5x-86rv",
        "aliases": ["CVE-2020-13254"],
        "package": "django",
        "ecosystem": "PyPI",
        "affected_spec": ">=2.2.0,<2.2.13",
        "fixed_version": "2.2.13",
        "severity": VulnerabilitySeverity.MEDIUM,
        "cvss_score": 5.3,
        "summary": "Django potential data leakage via malformed cache key strings in memcached.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-13254"]
    },
    {
        "advisory_id": "GHSA-jfhm-5ghh-2f97",
        "aliases": ["CVE-2020-8203"],
        "package": "lodash",
        "ecosystem": "npm",
        "affected_spec": "<4.17.21",
        "fixed_version": "4.17.21",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 7.4,
        "summary": "Lodash Prototype Pollution via zipObjectDeep function.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"]
    },
    {
        "advisory_id": "GHSA-4w2v-q235-gw99",
        "aliases": ["CVE-2020-28168"],
        "package": "axios",
        "ecosystem": "npm",
        "affected_spec": "<0.21.1",
        "fixed_version": "0.21.1",
        "severity": VulnerabilitySeverity.HIGH,
        "cvss_score": 7.7,
        "summary": "Axios Server-Side Request Forgery vulnerability via insecure follow-redirect handling.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28168"]
    }
]


def query_local_advisories(package_name: str, version_str: str, ecosystem: str = "PyPI") -> List[AdvisoryReference]:
    """Query local curated advisory database for matching package and version."""
    matches = []
    norm_pkg = package_name.strip().lower().replace("_", "-")
    
    try:
        parsed_v = parse_version(version_str)
    except Exception:
        return matches

    for entry in EMBEDDED_ADVISORIES:
        if entry["ecosystem"].lower() != ecosystem.lower():
            continue
        entry_pkg = entry["package"].strip().lower().replace("_", "-")
        if entry_pkg != norm_pkg:
            continue
        
        try:
            spec = SpecifierSet(entry["affected_spec"])
            if parsed_v in spec:
                matches.append(
                    AdvisoryReference(
                        advisory_id=entry["advisory_id"],
                        aliases=entry.get("aliases", []),
                        summary=entry["summary"],
                        severity=entry["severity"],
                        cvss_score=entry.get("cvss_score"),
                        affected_package=entry["package"],
                        affected_versions=entry["affected_spec"],
                        fixed_version=entry.get("fixed_version"),
                        references=entry.get("references", [])
                    )
                )
        except Exception:
            continue

    return matches

