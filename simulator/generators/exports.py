"""
Stateful export job store for /assets/export and /vulns/export.

Each export starts as QUEUED, transitions to PROCESSING on the next poll,
and to FINISHED after Config.EXPORT_POLLS_TO_FINISH polls - simulating a
real Tenable export that takes a few polling cycles.
"""
from threading import Lock

from config import Config

from .base import new_uuid


class ExportStore:
    def __init__(self, kind):
        self.kind = kind  # 'assets' or 'vulns'
        self._lock = Lock()
        self._jobs = {}  # uuid -> {status, polls, chunks_available, chunk_size, num_assets, filters}

    def create(self, payload):
        uuid_ = new_uuid()
        with self._lock:
            self._jobs[uuid_] = {
                'uuid': uuid_,
                'status': 'QUEUED',
                'polls': 0,
                'chunk_size': payload.get('chunk_size', 5000) if self.kind == 'assets' else None,
                'num_assets': payload.get('num_assets', 500) if self.kind == 'vulns' else None,
                'filters': payload.get('filters') or {},
                'chunks_available': [],
            }
        return uuid_

    def get_status(self, uuid_):
        with self._lock:
            job = self._jobs.get(uuid_)
            if job is None:
                return None
            job['polls'] += 1
            if job['status'] == 'QUEUED' and job['polls'] >= 1:
                job['status'] = 'PROCESSING'
            if job['status'] == 'PROCESSING' and job['polls'] >= Config.EXPORT_POLLS_TO_FINISH:
                job['status'] = 'FINISHED'
                job['chunks_available'] = [1]  # single chunk (all data)
            return {
                'status': job['status'],
                'chunks_available': job['chunks_available'],
                'total_chunks': len(job['chunks_available']),
            }

    def has(self, uuid_):
        return uuid_ in self._jobs
