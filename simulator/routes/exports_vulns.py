"""
Vulnerabilities export flow (async), stateless.

  POST /vulns/export                          - create export job (returns a UUID)
  GET  /vulns/export/<uuid>/status            - always FINISHED (see exports.py note)
  GET  /vulns/export/<uuid>/chunks/<chunk_id> - static chunk of every vuln finding
"""
from flask import Blueprint, jsonify, request

from auth import require_api_keys
from generators.assets import vuln_export_row
from generators.catalog import ASSETS
from generators.exports import create_export_uuid, is_valid_export_uuid

from ._helpers import not_found


vulns_export_bp = Blueprint('vulns_export', __name__, url_prefix='/vulns/export')


@vulns_export_bp.route('', methods=['POST'])
@require_api_keys
def initiate_export():
    _ = request.get_json(silent=True) or {}
    return jsonify({'export_uuid': create_export_uuid()}), 200


@vulns_export_bp.route('/<export_uuid>/status', methods=['GET'])
@require_api_keys
def export_status(export_uuid):
    if not is_valid_export_uuid(export_uuid):
        return not_found(f'Vulns export {export_uuid} not found')
    return jsonify({
        'status': 'FINISHED',
        'chunks_available': [1],
        'total_chunks': 1,
    }), 200


@vulns_export_bp.route('/<export_uuid>/chunks/<int:chunk_id>', methods=['GET'])
@require_api_keys
def export_chunk(export_uuid, chunk_id):
    if not is_valid_export_uuid(export_uuid):
        return not_found(f'Vulns export {export_uuid} not found')
    rows = []
    for a in ASSETS:
        for v in a['_vulns']:
            rows.append(vuln_export_row(a, v))
    return jsonify(rows), 200
