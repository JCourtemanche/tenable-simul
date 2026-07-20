"""
Workbench endpoints (used for get-asset-details, get-vulnerability-details, ...).
  GET /workbenches/assets/<uuid>/info
  GET /workbenches/assets/<uuid>/vulnerabilities
  GET /workbenches/vulnerabilities/<plugin_id>/info
  GET /api/v3/assets/<uuid>/attributes
"""
from flask import Blueprint, jsonify

from auth import require_api_keys
from generators.assets import (
    workbench_asset_info,
    workbench_asset_vulnerabilities,
    workbench_vuln_info,
)
from generators.catalog import (
    ASSETS_BY_UUID,
    VULNERABILITIES_BY_PLUGIN_ID,
    assets_affected_by,
)

from ._helpers import not_found


workbenches_bp = Blueprint('workbenches', __name__)


@workbenches_bp.route('/workbenches/assets/<asset_uuid>/info', methods=['GET'])
@require_api_keys
def get_asset_info(asset_uuid):
    asset = ASSETS_BY_UUID.get(asset_uuid)
    if asset is None:
        return not_found(f'Asset {asset_uuid} not found')
    return jsonify(workbench_asset_info(asset)), 200


@workbenches_bp.route('/workbenches/assets/<asset_uuid>/vulnerabilities', methods=['GET'])
@require_api_keys
def get_asset_vulnerabilities(asset_uuid):
    asset = ASSETS_BY_UUID.get(asset_uuid)
    if asset is None:
        return not_found(f'Asset {asset_uuid} not found')
    return jsonify(workbench_asset_vulnerabilities(asset)), 200


@workbenches_bp.route('/workbenches/vulnerabilities/<int:plugin_id>/info', methods=['GET'])
@require_api_keys
def get_vulnerability_info(plugin_id):
    v = VULNERABILITIES_BY_PLUGIN_ID.get(plugin_id)
    if v is None:
        return not_found(f'Plugin {plugin_id} not found')
    return jsonify(workbench_vuln_info(v, assets_affected_by(plugin_id))), 200


@workbenches_bp.route('/api/v3/assets/<asset_uuid>/attributes', methods=['GET'])
@require_api_keys
def get_asset_attributes(asset_uuid):
    asset = ASSETS_BY_UUID.get(asset_uuid)
    if asset is None:
        return not_found(f'Asset {asset_uuid} not found')
    return jsonify({
        'attributes': [{'name': t['category'], 'value': t['value']} for t in asset['tags']],
    }), 200
