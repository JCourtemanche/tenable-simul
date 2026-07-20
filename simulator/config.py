import os


class Config:
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))

    # Tenable.io uses `X-ApiKeys: accessKey=<a>; secretKey=<s>`
    AUTH_ACCESS_KEY = os.environ.get('TENABLE_ACCESS_KEY', 'tenable-access-key')
    AUTH_SECRET_KEY = os.environ.get('TENABLE_SECRET_KEY', 'tenable-secret-key')

    # Fleet sizing
    EXTRA_ASSETS = int(os.environ.get('EXTRA_ASSETS', 12))
    VULN_COUNT = int(os.environ.get('VULN_COUNT', 40))
    AUDIT_LOG_COUNT = int(os.environ.get('AUDIT_LOG_COUNT', 200))

    # How many polls until an export transitions from QUEUED -> PROCESSING -> FINISHED
    EXPORT_POLLS_TO_FINISH = int(os.environ.get('EXPORT_POLLS_TO_FINISH', 2))
