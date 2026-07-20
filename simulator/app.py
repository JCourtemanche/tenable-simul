"""Tenable.io API simulator - Flask entrypoint."""
import logging

from flask import Flask, jsonify

from config import Config
from routes.audit_log import audit_log_bp
from routes.exports_assets import assets_export_bp
from routes.exports_vulns import vulns_export_bp
from routes.scans import filters_bp, scans_bp
from routes.workbenches import workbenches_bp


def create_app():
    app = Flask(__name__)
    app.url_map.strict_slashes = False

    logging.basicConfig(
        level=logging.INFO if Config.DEBUG else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info('Starting Tenable.io API Simulator')

    app.register_blueprint(scans_bp)
    app.register_blueprint(filters_bp)
    app.register_blueprint(workbenches_bp)
    app.register_blueprint(assets_export_bp)
    app.register_blueprint(vulns_export_bp)
    app.register_blueprint(audit_log_bp)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'Tenable.io API Simulator',
            'version': '1.0.0',
        }), 200

    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            'service': 'Tenable.io API Simulator',
            'version': '1.0.0',
            'auth': 'X-ApiKeys header: accessKey=<a>; secretKey=<s>',
            'endpoints': {
                'GET /scans': 'List scans (folder_id / last_modification_date filters)',
                'GET /scans/<id>': 'Scan report (info + history)',
                'GET /scans/<id>/history': 'Scan history',
                'POST /scans/<id>/launch|pause|resume': 'Scan transitions',
                'POST /scans/<id>/export': 'Initiate scan export',
                'GET /scans/<id>/export/<file>/status|download': 'Export status + download (PDF or CSV)',
                'GET /filters/scans/reports': 'Filter definitions',
                'GET /workbenches/assets/<uuid>/info': 'Asset details',
                'GET /workbenches/assets/<uuid>/vulnerabilities': 'Vulnerabilities on asset',
                'GET /workbenches/vulnerabilities/<plugin_id>/info': 'Plugin detail (severity, CVE, CVSS, solution)',
                'GET /api/v3/assets/<uuid>/attributes': 'Asset attributes',
                'POST /assets/export + /assets/export/<uuid>/status + /chunks/<id>': 'Async assets export (fetch-assets flow)',
                'POST /vulns/export + /vulns/export/<uuid>/status + /chunks/<id>': 'Async vulns export (fetch-assets flow)',
                'GET /audit-log/v1/events': 'Audit log events (fetch-events flow)',
                'GET /health': 'Health check (no auth)',
            },
        }), 200

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({'statusCode': 404, 'error': 'Not Found', 'message': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Internal server error: {error}')
        return jsonify({'statusCode': 500, 'error': 'Internal Server Error', 'message': str(error)}), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
