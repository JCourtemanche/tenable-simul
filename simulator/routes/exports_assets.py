"""
Asset export flow (async):
  POST /assets/export                          - create export job
  GET  /assets/export/<uuid>/status            - poll status
  GET  /assets/export/<uuid>/chunks/<chunk_id> - download chunk
"""
from flask import Blueprint, jsonify, request

from auth import require_api_keys
from generators.assets import asset_export_row
from generators.catalog import ASSETS, ASSETS_EXPORT

from ._helpers import not_found


assets_export_bp = Blueprint('assets_export', __name__, url_prefix='/assets/export')


@assets_export_bp.route('', methods=['POST'])
@require_api_keys
def initiate_export():
    payload = request.get_json(silent=True) or {}
    uuid_ = ASSETS_EXPORT.create(payload)
    return jsonify({'export_uuid': uuid_}), 200


@assets_export_bp.route('/<export_uuid>/status', methods=['GET'])
@require_api_keys
def export_status(export_uuid):
    status = ASSETS_EXPORT.get_status(export_uuid)
    if status is None:
        return not_found(f'Assets export {export_uuid} not found')
    return jsonify(status), 200


@assets_export_bp.route('/<export_uuid>/chunks/<int:chunk_id>', methods=['GET'])
@require_api_keys
def export_chunk(export_uuid, chunk_id):
    if not ASSETS_EXPORT.has(export_uuid):
        return not_found(f'Assets export {export_uuid} not found')
    # Return all assets in a single chunk (chunk_id 1)
    return jsonify([asset_export_row(a) for a in ASSETS]), 200
