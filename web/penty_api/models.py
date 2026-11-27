import hashlib
import secrets

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

TOKEN_PREFIX = 'rgp_'


def hash_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


class PentyApiToken(models.Model):
    """API token for service-to-service calls. Only the SHA-256 hash is stored."""
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='penty_api_tokens')
    name = models.CharField(max_length=200)
    key_hash = models.CharField(max_length=64, unique=True)
    key_prefix = models.CharField(max_length=16)
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-id']

    def __str__(self):
        return f'{self.name} ({self.key_prefix}…)'

    @property
    def is_active(self):
        return self.revoked_at is None

    @classmethod
    def issue(cls, user, name):
        """Create a token and return (instance, raw_key). The raw key is shown once."""
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        token = cls.objects.create(
            user=user,
            name=name,
            key_hash=hash_token(raw),
            key_prefix=raw[:12],
        )
        return token, raw


class PentyIntegrationConfig(models.Model):
    """Singleton (pk=1) holding webhook settings."""
    id = models.AutoField(primary_key=True)
    webhook_enabled = models.BooleanField(default=False)
    webhook_secret = models.CharField(max_length=200, blank=True, default='')
    # If set, every callback_url must start with this prefix (SSRF guard).
    allowed_callback_prefix = models.CharField(max_length=500, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class PentyScanLink(models.Model):
    """Links a reNgine scan/subscan started through this API to its Penty-side reference."""
    KIND_SCAN = 'scan'
    KIND_SUBSCAN = 'subscan'
    KIND_CHOICES = ((KIND_SCAN, 'Scan'), (KIND_SUBSCAN, 'Subscan'))

    id = models.AutoField(primary_key=True)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    scan_history = models.ForeignKey(
        'startScan.ScanHistory', on_delete=models.CASCADE, null=True, blank=True, related_name='penty_links')
    subscan = models.ForeignKey(
        'startScan.SubScan', on_delete=models.CASCADE, null=True, blank=True, related_name='penty_links')
    # For subscans the SubScan row is created later inside the celery task; we match it by
    # the celery task id returned from apply_async (SubScan.celery_ids[0]).
    celery_task_id = models.CharField(max_length=100, blank=True, default='', db_index=True)
    subdomain_id = models.IntegerField(null=True, blank=True)
    task = models.CharField(max_length=100, blank=True, default='')
    external_ref = models.CharField(max_length=200, blank=True, default='')
    callback_url = models.CharField(max_length=1000, blank=True, default='')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_notified_status = models.IntegerField(null=True, blank=True)
    last_delivery_at = models.DateTimeField(null=True, blank=True)
    last_delivery_ok = models.BooleanField(null=True, blank=True)
    last_delivery_error = models.CharField(max_length=500, blank=True, default='')

    class Meta:
        ordering = ['-id']
