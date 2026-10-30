"""OSV (Open Source Vulnerabilities) API Client with local caching and offline fallback."""

from typing import List, Dict, Any, Optional
import requests
from ..models import AdvisoryReference, VulnerabilitySeverity
from .advisory_db import query_local_advisories

OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"

_OSV_CACHE: Dict[str, List[AdvisoryReference]] = {}


def _map_osv_severity(vuln_data: Dict[str, Any]) -> VulnerabilitySeverity:
    """Map OSV database severity ratings to standard VulnerabilitySeverity enum."""
    severities = vuln_data.get("severity", [])
    if severities:
        for s in severities:
            score = s.get("score")
            if score and isinstance(score, (int, float)):
                if score >= 9.0:
                    return VulnerabilitySeverity.CRITICAL
                elif score >= 7.0:
                    return VulnerabilitySeverity.HIGH
                elif score >= 4.0:
                    return VulnerabilitySeverity.MEDIUM
                else:
                    return VulnerabilitySeverity.LOW

    # Fallback to database_specific or summary inspection
    db_spec = vuln_data.get("database_specific", {})
    sev = str(db_spec.get("severity", "")).upper()
    if "CRITICAL" in sev:
        return VulnerabilitySeverity.CRITICAL
    elif "HIGH" in sev:
        return VulnerabilitySeverity.HIGH
    elif "MODERATE" in sev or "MEDIUM" in sev:
        return VulnerabilitySeverity.MEDIUM
    elif "LOW" in sev:
        return VulnerabilitySeverity.LOW

    return VulnerabilitySeverity.HIGH


def query_package_vulnerabilities(
    package_name: str,
    version: str,
    ecosystem: str = "PyPI",
    allow_network: bool = True
) -> List[AdvisoryReference]:
    """Query OSV API for package vulnerabilities, falling back to local advisory DB on failure/offline."""
    cache_key = f"{ecosystem}:{package_name}:{version}".lower()
    if cache_key in _OSV_CACHE:
        return _OSV_CACHE[cache_key]

    results: List[AdvisoryReference] = []

    if allow_network:
        try:
            payload = {
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            response = requests.post(OSV_QUERY_ENDPOINT, json=payload, timeout=3.0)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                for vuln in vulns:
                    adv_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary") or vuln.get("details", "Known vulnerability advisory")
                    aliases = vuln.get("aliases", [])
                    references = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]
                    severity = _map_osv_severity(vuln)
                    
                    fixed_ver: Optional[str] = None
                    for affected in vuln.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_ver = event["fixed"]
                                    break
                    
                    results.append(
                        AdvisoryReference(
                            advisory_id=adv_id,
                            aliases=aliases,
                            summary=summary[:200],
                            severity=severity,
                            affected_package=package_name,
                            affected_versions=version,
                            fixed_version=fixed_ver,
                            references=references[:3]
                        )
                    )
        except Exception:
            # Network failed or timed out: gracefully fallback to local advisory DB
            pass

    # If no results from network, query the local database
    if not results:
        results = query_local_advisories(package_name, version, ecosystem)

    _OSV_CACHE[cache_key] = results
    return results

