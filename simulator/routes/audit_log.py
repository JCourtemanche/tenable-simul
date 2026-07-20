"""
Audit log endpoint:
  GET /audit-log/v1/events?f=date.gt:...&f=date.lt:...&limit=...
"""
from flask import Blueprint, jsonify, request

from auth import require_api_keys
from generators.catalog import AUDIT_LOGS


audit_log_bp = Blueprint('audit_log', __name__, url_prefix='/audit-log/v1')


@audit_log_bp.route('/events', methods=['GET'])
@require_api_keys
def list_events():
    try:
        limit = int(request.args.get('limit', 5000))
    except (TypeError, ValueError):
        limit = 5000
    events = AUDIT_LOGS[:limit]
    return jsonify({'events': events, 'pagination': {'total': len(events), 'offset': 0, 'limit': limit}}), 200
