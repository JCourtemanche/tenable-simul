"""
Tenable.io asset catalog + per-asset vulnerability finding builder.
"""
import random
from datetime import timedelta

from .base import (
    EXTRA_OS,
    USERS,
    epoch_s,
    fake_mac,
    iso_z,
    new_uuid,
    os_for_persona,
    past_date,
)


EXTRA_SERVER_SEED = [
    ('srv-web-01.business.org',    '10.10.20.51', 'Windows Server 2019'),
    ('srv-web-02.business.org',    '10.10.20.52', 'Ubuntu 22.04 LTS'),
    ('srv-db-01.business.org',     '10.10.20.53', 'Debian 12'),
    ('srv-db-02.business.org',     '10.10.20.54', 'Debian 12'),
    ('srv-mail.business.org',      '10.10.20.55', 'Windows Server 2019'),
    ('srv-ad-01.business.org',     '10.10.20.56', 'Windows Server 2022'),
    ('srv-fs-01.business.org',     '10.10.20.57', 'Windows Server 2019'),
    ('srv-vpn.business.org',       '10.10.20.58', 'Ubuntu 20.04 LTS'),
    ('srv-monitoring.business.org','10.10.20.59', 'Debian 12'),
    ('srv-ci.business.org',        '10.10.20.60', 'Ubuntu 22.04 LTS'),
    ('cloud-lb-01.business.org',   '10.20.30.10', 'Ubuntu 22.04 LTS'),
    ('cloud-app-01.business.org',  '10.20.30.11', 'Debian 12'),
]


def _persona_assets(vuln_pool, r):
    assets = []
    for idx, persona in enumerate(USERS):
        os_str, os_family = os_for_persona(persona)
        vulns = r.sample(vuln_pool, k=r.randint(4, 12))
        last_seen = past_date(0, 3)
        first_seen = past_date(180, 800)
        assets.append({
            'id': new_uuid(),  # asset UUID
            '_int_id': 10_000 + idx,  # internal integer id
            'has_agent': True,
            'has_plugin_results': True,
            'created_at': iso_z(first_seen),
            'terminated_at': None,
            'terminated_by': None,
            'updated_at': iso_z(last_seen),
            'deleted_at': None,
            'deleted_by': None,
            'first_seen': iso_z(first_seen),
            'last_seen': iso_z(last_seen),
            'first_scan_time': iso_z(first_seen),
            'last_scan_time': iso_z(last_seen),
            'last_authenticated_scan_date': iso_z(last_seen),
            'last_licensed_scan_date': iso_z(last_seen),
            'last_scan_id': f'scan-{5000 + idx}',
            'last_schedule_id': f'template-{100 + idx}',
            'ipv4s': [persona['internal_ip']],
            'ipv6s': [],
            'fqdns': [f"{persona['hostname']}.business.org"],
            'mac_addresses': [fake_mac()],
            'netbios_names': [persona['hostname'][:15].upper()],
            'operating_systems': [os_str],
            'system_types': ['general-purpose' if persona.get('machine_type') != 'mobile' else 'mobile'],
            'hostnames': [persona['hostname']],
            'agent_names': [persona['hostname']],
            'installed_software': [
                f'cpe:/o:microsoft:{os_str.lower().split()[-1]}',
            ],
            'sources': [{'name': 'NESSUS_AGENT', 'first_seen': iso_z(first_seen), 'last_seen': iso_z(last_seen)}],
            'tags': [
                {'category': 'Environment', 'value': 'Business Corp'},
                {'category': 'AssetType', 'value': 'Persona'},
            ],
            'acr_score': r.randint(2, 5),
            'acr_drivers': [],
            'exposure_score': r.randint(200, 700),
            'network_id': '00000000-0000-0000-0000-000000000000',
            '_vulns': vulns,
            '_hostname': persona['hostname'],
            '_type': 'workstation',
        })
    return assets


def _extra_assets(vuln_pool, r, count):
    assets = []
    seed = EXTRA_SERVER_SEED[:count]
    for idx, (hostname, ip, os_name) in enumerate(seed):
        os_str, os_family = EXTRA_OS[os_name]
        vulns = r.sample(vuln_pool, k=r.randint(8, 20))
        last_seen = past_date(0, 5)
        first_seen = past_date(400, 1600)
        assets.append({
            'id': new_uuid(),
            '_int_id': 20_000 + idx,
            'has_agent': True,
            'has_plugin_results': True,
            'created_at': iso_z(first_seen),
            'terminated_at': None,
            'terminated_by': None,
            'updated_at': iso_z(last_seen),
            'deleted_at': None,
            'deleted_by': None,
            'first_seen': iso_z(first_seen),
            'last_seen': iso_z(last_seen),
            'first_scan_time': iso_z(first_seen),
            'last_scan_time': iso_z(last_seen),
            'last_authenticated_scan_date': iso_z(last_seen),
            'last_licensed_scan_date': iso_z(last_seen),
            'last_scan_id': f'scan-{5100 + idx}',
            'last_schedule_id': f'template-{200 + idx}',
            'ipv4s': [ip],
            'ipv6s': [],
            'fqdns': [hostname],
            'mac_addresses': [fake_mac()],
            'netbios_names': [hostname.split('.')[0][:15].upper()],
            'operating_systems': [os_str],
            'system_types': ['general-purpose'],
            'hostnames': [hostname.split('.')[0]],
            'agent_names': [hostname.split('.')[0]],
            'installed_software': [f'cpe:/o:{os_family}:server'],
            'sources': [{'name': 'NESSUS_SCAN', 'first_seen': iso_z(first_seen), 'last_seen': iso_z(last_seen)}],
            'tags': [
                {'category': 'Environment', 'value': 'Business Corp'},
                {'category': 'AssetType', 'value': 'Server'},
                {'category': 'Criticality', 'value': 'High' if 'db' in hostname or 'ad' in hostname else 'Medium'},
            ],
            'acr_score': r.randint(3, 5),
            'exposure_score': r.randint(400, 950),
            'acr_drivers': [],
            'network_id': '00000000-0000-0000-0000-000000000000',
            '_vulns': vulns,
            '_hostname': hostname.split('.')[0],
            '_type': 'server',
        })
    return assets


def build_assets_catalog(vuln_pool, extra_count=12):
    r = random.Random(101010)
    assets = _persona_assets(vuln_pool, r)
    assets.extend(_extra_assets(vuln_pool, r, extra_count))
    return assets


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def asset_export_row(asset):
    """
    One row of a /assets/export/<uuid>/chunks/<id> response - matches the
    Tenable assets export schema.
    """
    return {k: v for k, v in asset.items() if not k.startswith('_')}


def workbench_asset_info(asset):
    """/workbenches/assets/<uuid>/info response body."""
    info = asset_export_row(asset)
    # Wrap in "info" as per Tenable API
    return {
        'info': {
            'id': asset['id'],
            'has_agent': asset['has_agent'],
            'created_at': asset['created_at'],
            'updated_at': asset['updated_at'],
            'first_seen': asset['first_seen'],
            'last_seen': asset['last_seen'],
            'last_scan_target': asset['ipv4s'][0] if asset['ipv4s'] else None,
            'last_authenticated_scan_date': asset['last_authenticated_scan_date'],
            'last_licensed_scan_date': asset['last_licensed_scan_date'],
            'sources': asset['sources'],
            'tags': asset['tags'],
            'interfaces': [{
                'name': 'eth0',
                'ipv4': asset['ipv4s'],
                'ipv6': asset['ipv6s'],
                'mac_address': asset['mac_addresses'],
                'fqdn': asset['fqdns'],
            }],
            'network_id': asset['network_id'],
            'ipv4': asset['ipv4s'],
            'ipv6': asset['ipv6s'],
            'fqdn': asset['fqdns'],
            'mac_address': asset['mac_addresses'],
            'netbios_name': asset['netbios_names'],
            'operating_system': asset['operating_systems'],
            'system_type': asset['system_types'],
            'hostname': asset['hostnames'],
            'agent_name': asset['agent_names'],
            'installed_software': asset['installed_software'],
            'counts': {
                'vulnerabilities': {
                    'total': len(asset['_vulns']),
                    'severities': [
                        {'count': sum(1 for v in asset['_vulns'] if v['severity_str'] == s), 'level': i, 'name': s}
                        for i, s in enumerate(['info', 'low', 'medium', 'high', 'critical'])
                    ],
                },
                'audits': {'total': 0, 'statuses': []},
            },
            'acr_score': asset['acr_score'],
            'exposure_score': asset['exposure_score'],
        },
    }


def workbench_asset_vulnerabilities(asset):
    """/workbenches/assets/<uuid>/vulnerabilities response body."""
    vulns = [
        {
            'count': 1,
            'plugin_family': v['plugin_family'],
            'plugin_id': v['plugin_id'],
            'plugin_name': v['plugin_name'],
            'severity': v['severity'],
            'vulnerability_state': 'active',
            'accepted_count': 0,
            'recasted_count': 0,
            'counts_by_severity': [{'count': 1, 'value': v['severity']}],
        }
        for v in asset['_vulns']
    ]
    return {
        'vulnerabilities': vulns,
        'total_vulnerability_count': sum(v['count'] for v in vulns),
        'total_asset_count': 1,
    }


def vuln_export_row(asset, vuln):
    """
    One row of a /vulns/export/<uuid>/chunks/<id> response, mirroring the
    Tenable vulnerabilities export schema (asset + plugin + port).
    """
    return {
        'asset': {
            'uuid': asset['id'],
            'hostname': asset['_hostname'],
            'ipv4': asset['ipv4s'][0] if asset['ipv4s'] else None,
            'mac_address': asset['mac_addresses'][0] if asset['mac_addresses'] else None,
            'operating_system': asset['operating_systems'],
            'network_id': asset['network_id'],
            'tracked': True,
            'agent_uuid': asset['id'],
            'first_scan_time': asset['first_scan_time'],
            'last_scan_time': asset['last_scan_time'],
            'last_authenticated_results': asset['last_authenticated_scan_date'],
        },
        'output': f'Detected via authenticated scan. Related CVE: {vuln["cve"]}',
        'plugin': {
            'bid': [],
            'checks_for_default_account': False,
            'checks_for_malware': False,
            'cpe': [],
            'cve': [vuln['cve']],
            'cvss3_base_score': vuln['cvss3_base_score'],
            'cvss3_temporal_score': vuln['cvss3_temporal_score'],
            'cvss3_vector': {'raw': vuln['cvss3_vector']},
            'cvss_base_score': vuln['cvss_base_score'],
            'cvss_temporal_score': vuln['cvss_base_score'],
            'cvss_vector': {'raw': 'AV:N/AC:L/Au:N/C:C/I:C/A:C'},
            'description': vuln['description'],
            'exploit_available': vuln['exploit_available'],
            'exploited_by_malware': False,
            'exploited_by_nessus': False,
            'family': vuln['plugin_family'],
            'family_id': 4,
            'has_patch': vuln['has_patch'],
            'id': vuln['plugin_id'],
            'in_the_news': True,
            'name': vuln['plugin_name'],
            'modification_date': vuln['plugin_modification_date'],
            'publication_date': vuln['plugin_publication_date'],
            'patch_publication_date': vuln['patch_publication_date'],
            'risk_factor': vuln['severity_str'].title(),
            'see_also': vuln['see_also'],
            'solution': vuln['solution'],
            'synopsis': vuln['synopsis'],
            'type': 'remote',
            'vpr': {'score': vuln['vpr_score'], 'drivers': {'age_of_vuln': {'lower_bound': 366}}, 'updated': iso_z()},
            'vuln_publication_date': vuln['vuln_publication_date'],
            'unsupported_by_vendor': False,
        },
        'port': {'port': 0, 'protocol': 'TCP', 'service': 'ssl'},
        'scan': {
            'completed_at': asset['last_scan_time'],
            'schedule_uuid': f'template-uuid-{asset["_int_id"]}',
            'started_at': asset['last_scan_time'],
            'uuid': f'scan-uuid-{asset["_int_id"]}',
        },
        'severity': vuln['severity_str'],
        'severity_id': vuln['severity'],
        'severity_default_id': vuln['severity'],
        'severity_modification_type': 'NONE',
        'first_found': vuln['plugin_publication_date'],
        'last_found': asset['last_seen'],
        'state': 'OPEN',
    }


def workbench_vuln_info(vuln, affected_assets):
    """
    /workbenches/vulnerabilities/<plugin_id>/info response body.
    """
    return {
        'info': {
            'count': len(affected_assets),
            'description': vuln['description'],
            'discovery': {
                'seen_first': vuln['plugin_publication_date'],
                'seen_last': iso_z(),
            },
            'plugin_details': {
                'family': vuln['plugin_family'],
                'modification_date': vuln['plugin_modification_date'],
                'name': vuln['plugin_name'],
                'publication_date': vuln['plugin_publication_date'],
                'severity': vuln['severity'],
                'type': 'remote',
                'version': '1.0',
            },
            'reference_information': vuln['reference_information'],
            'risk_information': {
                'cvss3_base_score': str(vuln['cvss3_base_score']),
                'cvss3_temporal_score': str(vuln['cvss3_temporal_score']),
                'cvss3_temporal_vector': vuln['cvss3_vector'],
                'cvss3_vector': vuln['cvss3_vector'],
                'cvss_base_score': str(vuln['cvss_base_score']),
                'cvss_temporal_score': str(vuln['cvss_base_score']),
                'cvss_temporal_vector': 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
                'cvss_vector': 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
                'risk_factor': vuln['severity_str'].title(),
                'stig_severity': None,
            },
            'see_also': vuln['see_also'],
            'severity': vuln['severity'],
            'solution': vuln['solution'],
            'synopsis': vuln['synopsis'],
            'vpr': {'score': vuln['vpr_score']},
            'vuln_count': len(affected_assets),
            'vulnerability_information': {
                'asset_inventory': None,
                'cpe': None,
                'default_account': False,
                'exploit_available': vuln['exploit_available'],
                'exploited_by_malware': False,
                'exploited_by_nessus': False,
                'in_the_news': True,
                'malware': False,
                'patch_publication_date': vuln['patch_publication_date'],
                'vulnerability_publication_date': vuln['vuln_publication_date'],
            },
        },
    }
