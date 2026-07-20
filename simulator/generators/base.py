"""
Shared helpers + persona imports for the Tenable.io simulator.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

from faker import Faker

from xsiam_shared import (
    USERS,
    INTERNAL_IPS,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_URLS,
    MALICIOUS_FILES,
    DOMAIN,
    COMPANY_NAME,
)

fake = Faker()
Faker.seed(4004)
random.seed(4004)


def now_utc():
    return datetime.now(timezone.utc)


def iso_z(dt=None):
    """Tenable dates: 2026-07-20T14:42:47.123Z"""
    if dt is None:
        dt = now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def epoch_s(dt=None):
    if dt is None:
        dt = now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def past_date(min_days=1, max_days=365):
    return now_utc() - timedelta(days=random.randint(min_days, max_days))


def new_uuid():
    return str(uuid.uuid4())


def fake_mac():
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))


# ---------------------------------------------------------------------------
# Tenable OS strings (map personas + generated servers to what Tenable emits)
# ---------------------------------------------------------------------------

PERSONA_OS = {
    'Windows 10 Pro':     ('Microsoft Windows 10 Pro',                        'windows'),
    'Windows 11 Pro':     ('Microsoft Windows 11 Pro',                        'windows'),
    'macOS 13 Ventura':   ('Apple macOS 13.6.5 Ventura',                      'mac_osx'),
    'macOS 14 Sonoma':    ('Apple macOS 14.5 Sonoma',                         'mac_osx'),
    'iOS 17':             ('Apple iOS 17.4',                                  'ios'),
}

EXTRA_OS = {
    'Ubuntu 22.04 LTS':   ('Linux Kernel 5.15 on Ubuntu 22.04 LTS',           'linux'),
    'Ubuntu 20.04 LTS':   ('Linux Kernel 5.4 on Ubuntu 20.04 LTS',            'linux'),
    'Debian 12':          ('Linux Kernel 6.1 on Debian 12',                   'linux'),
    'Windows Server 2019':('Microsoft Windows Server 2019 Datacenter',        'windows'),
    'Windows Server 2022':('Microsoft Windows Server 2022 Datacenter',        'windows'),
}


def os_for_persona(persona):
    return PERSONA_OS.get(persona['os_name'], PERSONA_OS['Windows 10 Pro'])


# ---------------------------------------------------------------------------
# Tenable severity: numeric 0..4 and string form
# ---------------------------------------------------------------------------

SEVERITY_ID = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEVERITY_STR = {v: k for k, v in SEVERITY_ID.items()}


def severity_from_cvss(cvss_v3):
    if cvss_v3 is None:
        return 'medium'
    if cvss_v3 >= 9.0:
        return 'critical'
    if cvss_v3 >= 7.0:
        return 'high'
    if cvss_v3 >= 4.0:
        return 'medium'
    if cvss_v3 >= 0.1:
        return 'low'
    return 'info'
