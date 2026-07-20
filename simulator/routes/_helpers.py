"""Shared route helpers."""
from flask import jsonify


def not_found(msg):
    return jsonify({'statusCode': 404, 'error': 'Not Found', 'message': msg}), 404
