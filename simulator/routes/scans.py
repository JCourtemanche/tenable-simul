"""
Scan endpoints.
  GET  /scans                           - list scans
  GET  /scans/<id>                      - scan report (info + hosts + vulns + history)
  GET  /scans/<id>/history              - scan history
  POST /scans/<id>/launch               - launch scan
  POST /scans/<id>/pause                - pause scan
  POST /scans/<id>/resume               - resume scan
  POST /scans/<id>/export               - initiate export
  GET  /scans/<id>/export/<file>/status - export status
  GET  /scans/<id>/export/<file>/download - download exported file
  GET  /filters/scans/reports           - filter definitions
"""
import time
import uuid as _uuid

from flask import Blueprint, Response, jsonify, request

from auth import require_api_keys
from generators.catalog import SCAN_FILTERS, SCAN_STORE
from generators.scans import build_scan_report

from ._helpers import not_found


scans_bp = Blueprint('scans', __name__)


@scans_bp.route('/scans', methods=['GET'])
@require_api_keys
def list_scans():
    scans = SCAN_STORE.all()
    # Optional folder_id / last_modification_date filters
    if (fid := request.args.get('folder_id')):
        try:
            fid = int(fid)
            scans = [s for s in scans if s.get('folder_id') == fid]
        except (TypeError, ValueError):
            pass
    if (lmd := request.args.get('last_modification_date')):
        try:
            lmd = int(lmd)
            scans = [s for s in scans if s.get('last_modification_date', 0) >= lmd]
        except (TypeError, ValueError):
            pass
    return jsonify({
        'folders': [
            {'id': 8, 'name': 'My Scans',      'type': 'main', 'default_tag': 1, 'custom': 0, 'unread_count': 0},
            {'id': 9, 'name': 'Trash',         'type': 'trash','default_tag': 1, 'custom': 0, 'unread_count': 0},
        ],
        'scans': scans,
        'timestamp': int(time.time()),
    }), 200


@scans_bp.route('/scans/<scan_id>', methods=['GET'])
@require_api_keys
def get_scan_report(scan_id):
    scan = SCAN_STORE.get(scan_id)
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    return jsonify(build_scan_report(scan)), 200


@scans_bp.route('/scans/<scan_id>/history', methods=['GET'])
@require_api_keys
def scan_history(scan_id):
    scan = SCAN_STORE.get(scan_id)
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    return jsonify({
        'history': [
            {
                'id': i,
                'uuid': str(_uuid.uuid4()),
                'scan_uuid': scan['uuid'],
                'is_archived': False,
                'reindexing': None,
                'status': 'completed',
                'time_start': scan.get('starttime'),
                'time_end': scan.get('endtime'),
                'targets': scan['_target'],
            }
            for i in range(1, 4)
        ],
        'pagination': {'total': 3, 'limit': 100, 'offset': 0, 'sort': []},
    }), 200


@scans_bp.route('/scans/<scan_id>/launch', methods=['POST'])
@require_api_keys
def launch_scan(scan_id):
    scan = SCAN_STORE.transition(scan_id, 'running')
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    return jsonify({'scan_uuid': scan['uuid']}), 200


@scans_bp.route('/scans/<scan_id>/pause', methods=['POST'])
@require_api_keys
def pause_scan(scan_id):
    scan = SCAN_STORE.transition(scan_id, 'paused')
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    return jsonify({}), 200


@scans_bp.route('/scans/<scan_id>/resume', methods=['POST'])
@require_api_keys
def resume_scan(scan_id):
    scan = SCAN_STORE.transition(scan_id, 'running')
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    return jsonify({}), 200


@scans_bp.route('/scans/<scan_id>/export', methods=['POST'])
@require_api_keys
def initiate_scan_export(scan_id):
    scan = SCAN_STORE.get(scan_id)
    if scan is None:
        return not_found(f'Scan {scan_id} not found')
    file_id = str(int(time.time() * 1000))
    return jsonify({'file': file_id, 'temp_token': str(_uuid.uuid4())}), 200


@scans_bp.route('/scans/<scan_id>/export/<file_id>/status', methods=['GET'])
@require_api_keys
def scan_export_status(scan_id, file_id):
    return jsonify({'status': 'ready'}), 200


@scans_bp.route('/scans/<scan_id>/export/<file_id>/download', methods=['GET'])
@require_api_keys
def scan_export_download(scan_id, file_id):
    fmt = (request.args.get('format') or 'pdf').lower()
    if fmt == 'csv':
        body = (
            'Plugin ID,CVE,Severity,Host,Description\n'
            '200000,CVE-2021-44228,critical,192.168.1.1,Apache Log4j RCE\n'
            '200001,CVE-2024-3400,critical,10.10.20.51,PAN-OS command injection\n'
        )
        return Response(body, status=200, mimetype='text/csv')
    body = (
        b'%PDF-1.4\n%Tenable.io simulator - placeholder scan export\n'
        + f'%scan_id={scan_id} file_id={file_id}\n'.encode('ascii')
        + b'%%EOF\n'
    )
    return Response(body, status=200, mimetype='application/pdf')


# ---------------------------------------------------------------------------
# /filters/scans/reports (used by the fetch-vulns filter dropdown)
# ---------------------------------------------------------------------------

filters_bp = Blueprint('filters', __name__)


@filters_bp.route('/filters/scans/reports', methods=['GET'])
@require_api_keys
def list_scan_filters():
    return jsonify(SCAN_FILTERS), 200
