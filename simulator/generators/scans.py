"""Tenable.io scan catalog + live scan state store."""
import random
from datetime import timedelta
from threading import Lock

from .base import epoch_s, iso_z, new_uuid, past_date


SCAN_SEED = [
    (5001, 'Weekly Business Corp Scan',   'completed', 'local'),
    (5002, 'DR Site VM Scan',             'completed', 'local'),
    (5003, 'PCI Compliance Scan',         'completed', 'local'),
    (5004, 'Cloud Ops Continuous Scan',   'running',   'remote'),
    (5005, 'Dev Lab Ad-hoc Scan',         'completed', 'local'),
    (5006, 'Agent-based Fleet Scan',      'completed', 'agent'),
    (5007, 'External Perimeter Scan',     'completed', 'remote'),
    (5008, 'Patch Verification Scan',     'canceled',  'local'),
]

SCAN_TEMPLATES = [
    ('advanced', 'Advanced Scan',            'Configure a scan without using any recommendations.'),
    ('basic',    'Basic Network Scan',       'A full system scan suitable for any host.'),
    ('discovery','Host Discovery',           'Simple scan to discover live hosts and open ports.'),
    ('agent',    'Agent Scan',               'A scan run by Tenable agents.'),
    ('pci',      'Internal PCI Network Scan','A network scan for internal PCI DSS compliance.'),
    ('web',      'Web Application Tests',    'Scan web applications for vulnerabilities.'),
]


class ScanStore:
    """In-memory scan store used by launch / pause / resume / list actions."""
    def __init__(self):
        self._lock = Lock()
        self._scans = []
        self._next_id = 6000
        r = random.Random(4321)
        for sid, name, status, scan_type in SCAN_SEED:
            started = past_date(1, 20)
            duration = r.randint(300, 5400)
            self._scans.append({
                'id': sid,
                'uuid': new_uuid(),
                'name': name,
                'status': status,
                'type': scan_type,
                'read': True,
                'creation_date': epoch_s(started - timedelta(days=r.randint(30, 300))),
                'last_modification_date': epoch_s(started),
                'starttime': epoch_s(started),
                'endtime': epoch_s(started + timedelta(seconds=duration)) if status != 'running' else None,
                'enabled': True,
                'user_permissions': 128,
                'owner': 'admin@business.org',
                'rrules': 'FREQ=WEEKLY;INTERVAL=1;BYDAY=MO',
                'timezone': 'Europe/Paris',
                'has_triggers': False,
                'template_uuid': new_uuid(),
                'policy_id': 100 + sid % 5,
                'folder_id': 8,
                'target_network_uuid': '00000000-0000-0000-0000-000000000000',
                'shared': False,
                'wizard_uuid': new_uuid(),
                'schedule_uuid': f'schedule-{sid}',
                'control': True,
                'live_results': 0,
                '_scan_type_family': scan_type,
                '_target': '192.168.1.0/24,10.10.20.0/24',
            })

    def all(self):
        return list(self._scans)

    def get(self, sid):
        for s in self._scans:
            if str(s['id']) == str(sid) or s['uuid'] == str(sid):
                return s
        return None

    def transition(self, sid, target_status):
        with self._lock:
            s = self.get(sid)
            if s is None:
                return None
            s['status'] = target_status
            s['last_modification_date'] = epoch_s()
            if target_status in ('canceled', 'completed', 'stopped'):
                s['endtime'] = epoch_s()
            return s


def build_scan_filters():
    """/filters/scans/reports response body."""
    return {
        'filters': [
            {'name': 'host.hostname', 'readable_name': 'Hostname', 'operators': ['eq', 'neq', 'match'], 'control': {'type': 'entry', 'regex': '.*'}},
            {'name': 'plugin.attributes.plugin_name', 'readable_name': 'Plugin Name', 'operators': ['eq', 'match'], 'control': {'type': 'entry', 'regex': '.*'}},
            {'name': 'severity', 'readable_name': 'Severity', 'operators': ['eq', 'neq'],
             'control': {'type': 'dropdown', 'list': ['Info', 'Low', 'Medium', 'High', 'Critical']}},
            {'name': 'plugin.attributes.cvss3_base_score', 'readable_name': 'CVSS v3 Base Score',
             'operators': ['gt', 'lt', 'eq'], 'control': {'type': 'entry', 'regex': r'^\d+(\.\d+)?$'}},
        ],
    }


def build_scan_report(scan):
    """/scans/<id> response body."""
    return {
        'info': {
            'name': scan['name'],
            'id': scan['id'],
            'uuid': scan['uuid'],
            'status': scan['status'],
            'schedule_uuid': scan['schedule_uuid'],
            'targets': scan['_target'],
            'policy': f'policy-{scan["policy_id"]}',
            'scanner_name': 'Cloud Scanner',
            'scanner_start': scan['starttime'],
            'scanner_end': scan['endtime'],
            'timezone': scan['timezone'],
            'owner': scan['owner'],
        },
        'hosts': [],
        'vulnerabilities': [],
        'comphosts': [],
        'compliance': [],
        'filters': [],
        'history': [],
        'notes': [],
        'remediations': {'remediations': [], 'num_hosts': 0, 'num_cves': 0, 'num_impacted_hosts': 0},
    }
