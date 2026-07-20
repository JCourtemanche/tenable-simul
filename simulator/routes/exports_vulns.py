"""
Vulnerabilities export flow (async):
  POST /vulns/export                          - create export job
  GET  /vulns/export/<uuid>/status            - poll status
  GET  /vulns/export/<uuid>/chunks/<chunk_id> - download chunk
"""
from flask import Blueprint, jsonify, request

from auth import require_api_keys
from generators.assets import vuln_export_row
from generators.catalog import ASSETS, VULNS_EXPORT

from ._helpers import not_found


vulns_export_bp = Blueprint('vulns_export', __name__, url_prefix='/vulns/export')


@vulns_export_bp.route('', methods=['POST'])
@require_api_keys
def initiate_export():
    payload = request.get_json(silent=True) or {}
    uuid_ = VULNS_EXPORT.create(payload)
    return jsonify({'export_uuid': uuid_}), 200


@vulns_export_bp.route('/<export_uuid>/status', methods=['GET'])
@require_api_keys
def export_status(export_uuid):
    status = VULNS_EXPORT.get_status(export_uuid)
    if status is None:
        return not_found(f'Vulns export {export_uuid} not found')
    return jsonify(status), 200


@vulns_export_bp.route('/<export_uuid>/chunks/<int:chunk_id>', methods=['GET'])
@require_api_keys
def export_chunk(export_uuid, chunk_id):
    if not VULNS_EXPORT.has(export_uuid):
        return not_found(f'Vulns export {export_uuid} not found')
    rows = []
    for a in ASSETS:
        for v in a['_vulns']:
            rows.append(vuln_export_row(a, v))
    return jsonify(rows), 200
