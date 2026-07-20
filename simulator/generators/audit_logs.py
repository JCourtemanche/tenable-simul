"""Tenable.io audit log generator (/audit-log/v1/events)."""
import random
from datetime import timedelta

from .base import USERS, iso_z, past_date


ACTIONS = [
    ('user.login',              'session'),
    ('user.logout',             'session'),
    ('scan.launch',             'scan'),
    ('scan.finish',             'scan'),
    ('scan.pause',              'scan'),
    ('policy.create',           'policy'),
    ('policy.edit',             'policy'),
    ('user.impersonation.start','user'),
    ('user.impersonation.stop', 'user'),
    ('tag.create',              'tag'),
    ('tag.edit',                'tag'),
    ('asset.import',            'asset'),
]


def build_audit_logs(count=200):
    r = random.Random(9999)
    logs = []
    for i in range(count):
        u = r.choice(USERS)
        action, target_type = r.choice(ACTIONS)
        when = past_date(0, 30) + timedelta(minutes=r.randint(0, 59))
        logs.append({
            'id': f'audit-{i:06d}',
            'action': action,
            'crud': r.choice(['c', 'r', 'u', 'd']),
            'received': iso_z(when),
            'actor': {
                'id': f'user-{u["username"]}',
                'name': u['name'],
                'type': 'user',
                'email': u['email'],
            },
            'target': {
                'id': f'{target_type}-{r.randint(1000, 9999)}',
                'name': f'{target_type}-{r.randint(1000, 9999)}',
                'type': target_type,
            },
            'description': f'{u["name"]} performed {action}',
            'fields': [
                {'key': 'X-Forwarded-For', 'value': u['internal_ip']},
                {'key': 'X-Request-Uuid',  'value': f'req-{i:06d}'},
            ],
            'is_anonymous': False,
            'is_failure': False,
        })
    return logs
