"""Single instantiation of the whole Tenable.io dataset."""
from config import Config

from .assets import build_assets_catalog
from .audit_logs import build_audit_logs
from .scans import ScanStore, build_scan_filters
from .vulnerabilities import build_vulnerability_catalog


VULNERABILITIES = build_vulnerability_catalog(count=Config.VULN_COUNT)
ASSETS = build_assets_catalog(VULNERABILITIES, extra_count=Config.EXTRA_ASSETS)
AUDIT_LOGS = build_audit_logs(count=Config.AUDIT_LOG_COUNT)
SCAN_STORE = ScanStore()
SCAN_FILTERS = build_scan_filters()

VULNERABILITIES_BY_PLUGIN_ID = {v['plugin_id']: v for v in VULNERABILITIES}
VULNERABILITIES_BY_CVE = {v['cve']: v for v in VULNERABILITIES}
ASSETS_BY_UUID = {a['id']: a for a in ASSETS}


def assets_affected_by(plugin_id):
    return [a for a in ASSETS if any(v['plugin_id'] == plugin_id for v in a['_vulns'])]
