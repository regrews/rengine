"""Signed webhook delivery to Penty when a linked scan/subscan reaches a terminal status.

Signature: X-Penty-Signature: sha256=<hex HMAC-SHA256(secret, f"{timestamp}.{body}")>
           X-Penty-Timestamp: <unix seconds>
Webhooks are an accelerator only; Penty also polls, so a failed delivery is logged, not retried forever.
"""
import hashlib
import hmac
import json
import logging
import time

import requests
from django.utils import timezone

from penty_api.constants import SCAN_STATUS_NAMES

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 4
MAX_ATTEMPTS = 2


def sign(secret, timestamp, body):
    msg = f'{timestamp}.'.encode('utf-8') + body
    return 'sha256=' + hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()


def build_payload(link, status):
    payload = {
        'event': f'{link.kind}.finished',
        'kind': link.kind,
        'status': status,
        'status_name': SCAN_STATUS_NAMES.get(status, 'unknown'),
        'external_ref': link.external_ref or None,
        'scan_id': link.scan_history_id,
        'subscan_id': link.subscan_id,
        'sent_at': timezone.now().isoformat(),
    }
    return payload


def deliver(link, status, config, session=None):
    """Send the webhook; returns (ok, error). Never raises."""
    if not (config.webhook_enabled and config.webhook_secret and link.callback_url):
        return False, 'webhook disabled or not configured'

    body = json.dumps(build_payload(link, status), separators=(',', ':')).encode('utf-8')
    ts = str(int(time.time()))
    headers = {
        'Content-Type': 'application/json',
        'X-Penty-Timestamp': ts,
        'X-Penty-Signature': sign(config.webhook_secret, ts, body),
        'User-Agent': 'reNgine-penty-api',
    }
    http = session or requests
    error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = http.post(link.callback_url, data=body, headers=headers,
                             timeout=TIMEOUT_SECONDS, allow_redirects=False)
            if 200 <= resp.status_code < 300:
                return True, None
            error = f'HTTP {resp.status_code}'
        except requests.RequestException as exc:
            error = f'{type(exc).__name__}: {exc}'[:480]
        if attempt < MAX_ATTEMPTS:
            time.sleep(attempt)
    logger.warning('Penty webhook delivery failed for link %s: %s', link.id, error)
    return False, error
