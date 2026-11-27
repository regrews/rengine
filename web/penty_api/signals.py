"""Fire a webhook when a scan/subscan started through the Penty API reaches a terminal status.

Runs wherever the status is saved (celery worker for normal completion, web for aborts).
Delivery happens after the DB transaction commits and never raises into reNgine code.
"""
import logging

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from penty_api.constants import TERMINAL_STATUSES
from penty_api.models import PentyIntegrationConfig, PentyScanLink
from startScan.models import ScanHistory, SubScan

logger = logging.getLogger(__name__)


def _notify(link_ids, status):
    try:
        config = PentyIntegrationConfig.get()
        if not config.webhook_enabled:
            return
        from penty_api import webhook
        for link in PentyScanLink.objects.filter(id__in=link_ids):
            # Claim atomically so concurrent saves don't double-send.
            claimed = (
                PentyScanLink.objects
                .filter(pk=link.pk)
                .exclude(last_notified_status=status)
                .update(last_notified_status=status)
            )
            if not claimed:
                continue
            ok, error = webhook.deliver(link, status, config)
            PentyScanLink.objects.filter(pk=link.pk).update(
                last_delivery_at=timezone.now(),
                last_delivery_ok=ok,
                last_delivery_error=(error or '')[:500],
            )
    except Exception:  # never break reNgine's own save path
        logger.exception('Penty webhook notification failed')


@receiver(post_save, sender=ScanHistory, dispatch_uid='penty_api_scan_status')
def scan_status_changed(sender, instance, created, **kwargs):
    if instance.scan_status not in TERMINAL_STATUSES:
        return
    link_ids = list(
        PentyScanLink.objects
        .filter(kind=PentyScanLink.KIND_SCAN, scan_history_id=instance.id)
        .exclude(callback_url='')
        .exclude(last_notified_status=instance.scan_status)
        .values_list('id', flat=True)
    )
    if link_ids:
        transaction.on_commit(lambda: _notify(link_ids, instance.scan_status))


@receiver(post_save, sender=SubScan, dispatch_uid='penty_api_subscan_status')
def subscan_status_changed(sender, instance, created, **kwargs):
    # Bind the SubScan row to the link created at request time (matched by celery task id).
    celery_ids = list(instance.celery_ids or [])
    if celery_ids:
        PentyScanLink.objects.filter(
            kind=PentyScanLink.KIND_SUBSCAN,
            subscan__isnull=True,
            celery_task_id__in=celery_ids,
        ).update(subscan=instance, scan_history_id=instance.scan_history_id)

    if instance.status not in TERMINAL_STATUSES:
        return
    link_ids = list(
        PentyScanLink.objects
        .filter(kind=PentyScanLink.KIND_SUBSCAN, subscan_id=instance.id)
        .exclude(callback_url='')
        .exclude(last_notified_status=instance.status)
        .values_list('id', flat=True)
    )
    if link_ids:
        transaction.on_commit(lambda: _notify(link_ids, instance.status))
