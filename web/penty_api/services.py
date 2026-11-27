"""Business logic wrapping reNgine internals. Views stay thin; tests target these functions."""
import json
import logging
import os
import shutil
import uuid
from urllib.parse import urlparse

import validators
import yaml
from django.db import transaction
from django.template.defaultfilters import slugify
from django.utils import timezone

from dashboard.models import Project
from penty_api.constants import (
    ACTIVE_STATUSES, ENGINE_TASKS, RESULTS_ROOTS, SUBSCAN_TASKS,
)
from penty_api.models import PentyIntegrationConfig, PentyScanLink
from reNgine.definitions import ABORTED_TASK, LIVE_SCAN, RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan, Subdomain
from targetApp.models import Domain

logger = logging.getLogger(__name__)

SCAN_RESULTS_DIR = '/usr/src/scan_results'


class ApiError(Exception):
    """Raised by services; views map it to an HTTP response."""

    def __init__(self, message, status=400, field=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.field = field


# ---------------------------------------------------------------- helpers

def _str_list(value, field, max_items=5000, max_len=1000, lower=False):
    if value is None:
        return []
    if isinstance(value, str):
        value = [v for v in value.replace(',', '\n').split()]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ApiError(f'{field} must be a list of strings', field=field)
    cleaned = []
    for v in value:
        v = v.strip()
        if not v:
            continue
        if len(v) > max_len:
            raise ApiError(f'{field} item too long', field=field)
        cleaned.append(v.lower() if lower else v)
    if len(cleaned) > max_items:
        raise ApiError(f'{field} has too many items (max {max_items})', field=field)
    # de-duplicate, keep order
    return list(dict.fromkeys(cleaned))


def validate_callback_url(url):
    if not url:
        return ''
    if not isinstance(url, str) or len(url) > 1000:
        raise ApiError('callback_url is invalid', field='callback_url')
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ApiError('callback_url must be an http(s) URL', field='callback_url')
    prefix = PentyIntegrationConfig.get().allowed_callback_prefix
    if prefix and not url.startswith(prefix):
        raise ApiError('callback_url is not allowed by server configuration', field='callback_url')
    return url


def _external_ref(value):
    if value is None:
        return ''
    if not isinstance(value, str) or len(value) > 200:
        raise ApiError('external_ref must be a string (max 200 chars)', field='external_ref')
    return value


# ---------------------------------------------------------------- projects

def create_project(name):
    if not isinstance(name, str) or not name.strip():
        raise ApiError('name is required', field='name')
    name = name.strip()[:500]
    slug = slugify(name)
    if not slug:
        raise ApiError('name must contain letters or digits', field='name')
    existing = Project.objects.filter(slug=slug).first()
    if existing:
        return existing, False
    return Project.objects.create(name=name, slug=slug, insert_date=timezone.now()), True


# ---------------------------------------------------------------- targets

def normalize_target_name(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ApiError('name is required', field='name')
    name = raw.strip()
    if name.startswith('*.'):
        name = name[2:]
    name = name.lstrip('.')
    if validators.url(name):
        return name, 'url'
    if validators.ipv4(name) or validators.ipv6(name):
        return name, 'ip'
    name = name.lower().rstrip('.')
    if validators.domain(name):
        return name, 'domain'
    if validators.ipv4_cidr(name) or validators.ipv6_cidr(name):
        raise ApiError('CIDR ranges are not supported by reNgine; expand to individual IPs', field='name')
    raise ApiError('name must be a domain, IP address or URL', field='name')


@transaction.atomic
def create_target(project_slug, name, description=''):
    """Idempotent: returns (domain, created). 409 if the name belongs to another project."""
    from reNgine.database_utils import store_domain, store_ip, store_url

    project = Project.objects.filter(slug=project_slug).first() if project_slug else None
    if not project:
        raise ApiError('project_slug not found', status=404, field='project_slug')
    name, kind = normalize_target_name(name)
    description = (description or '')[:5000]

    lookup_name = urlparse(name).netloc if kind == 'url' else name
    existing = Domain.objects.filter(name=lookup_name).first()
    if existing:
        if existing.project_id != project.id:
            raise ApiError('target already exists in another project', status=409, field='name')
        return existing, False

    if kind == 'domain':
        store_domain(name, project, description, None)
    elif kind == 'url':
        store_url(name, project, description, None)
    else:
        store_ip(name, project, description, None)

    domain = Domain.objects.filter(name=lookup_name).first()
    if not domain:
        raise ApiError('reNgine refused to store the target', status=500)
    return domain, True


def delete_target(domain):
    if ScanHistory.objects.filter(domain=domain, scan_status__in=ACTIVE_STATUSES).exists():
        raise ApiError('target has running scans; stop them first', status=409)
    domain.delete()


# ---------------------------------------------------------------- engines

def validate_engine_yaml(text):
    if not isinstance(text, str) or not text.strip():
        raise ApiError('yaml_configuration is required', field='yaml_configuration')
    if len(text) > 200_000:
        raise ApiError('yaml_configuration too large', field='yaml_configuration')
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ApiError(f'invalid YAML: {exc}', field='yaml_configuration')
    if not isinstance(data, dict) or not data:
        raise ApiError('YAML must be a non-empty mapping of task -> config', field='yaml_configuration')
    tasks = [k for k in data if k in ENGINE_TASKS]
    if not tasks:
        raise ApiError(f'YAML must contain at least one task: {", ".join(ENGINE_TASKS)}',
                       field='yaml_configuration')
    for task in tasks:
        if data[task] is not None and not isinstance(data[task], dict):
            raise ApiError(f'config of task "{task}" must be a mapping', field='yaml_configuration')
    return tasks


def _validate_engine_name(name, exclude_id=None):
    if not isinstance(name, str) or not name.strip():
        raise ApiError('name is required', field='name')
    name = name.strip()[:200]
    qs = EngineType.objects.filter(engine_name__iexact=name)
    if exclude_id:
        qs = qs.exclude(pk=exclude_id)
    if qs.exists():
        raise ApiError('an engine with this name already exists', status=409, field='name')
    return name


def create_engine(name, yaml_text):
    name = _validate_engine_name(name)
    validate_engine_yaml(yaml_text)
    return EngineType.objects.create(engine_name=name, yaml_configuration=yaml_text, default_engine=False)


def update_engine(engine, name=None, yaml_text=None):
    if engine.default_engine:
        raise ApiError('built-in reNgine engines cannot be modified', status=403)
    if name is not None:
        engine.engine_name = _validate_engine_name(name, exclude_id=engine.id)
    if yaml_text is not None:
        validate_engine_yaml(yaml_text)
        engine.yaml_configuration = yaml_text
    engine.save()
    return engine


def delete_engine(engine):
    if engine.default_engine:
        raise ApiError('built-in reNgine engines cannot be deleted', status=403)
    # ScanHistory.scan_type is on_delete=CASCADE: deleting a used engine would wipe scan history.
    if ScanHistory.objects.filter(scan_type=engine).exists() or SubScan.objects.filter(engine=engine).exists():
        raise ApiError('engine is referenced by scans; it cannot be deleted', status=409)
    engine.delete()


# ---------------------------------------------------------------- scans

def start_scan(user, data):
    from reNgine.common_func import create_scan_object
    from reNgine.tasks import initiate_scan

    try:
        target_id = int(data.get('target_id'))
        engine_id = int(data.get('engine_id'))
    except (TypeError, ValueError):
        raise ApiError('target_id and engine_id are required integers')

    domain = Domain.objects.filter(pk=target_id).first()
    if not domain:
        raise ApiError('target not found', status=404, field='target_id')
    engine = EngineType.objects.filter(pk=engine_id).first()
    if not engine:
        raise ApiError('engine not found', status=404, field='engine_id')

    imported = _str_list(data.get('imported_subdomains'), 'imported_subdomains', lower=True)
    out_of_scope = _str_list(data.get('out_of_scope_subdomains'), 'out_of_scope_subdomains', lower=True)
    excluded_paths = _str_list(data.get('excluded_paths'), 'excluded_paths', max_items=500)
    starting_point_path = data.get('starting_point_path') or ''
    if not isinstance(starting_point_path, str) or len(starting_point_path) > 200:
        raise ApiError('starting_point_path must be a string (max 200 chars)', field='starting_point_path')
    starting_point_path = starting_point_path.strip()
    if starting_point_path and not starting_point_path.startswith('/'):
        raise ApiError('starting_point_path must start with "/"', field='starting_point_path')
    callback_url = validate_callback_url(data.get('callback_url'))
    external_ref = _external_ref(data.get('external_ref'))

    with transaction.atomic():
        scan_id = create_scan_object(host_id=domain.id, engine_id=engine.id, initiated_by_id=user.id)
        link = PentyScanLink.objects.create(
            kind=PentyScanLink.KIND_SCAN,
            scan_history_id=scan_id,
            external_ref=external_ref,
            callback_url=callback_url,
            created_by=user,
        )
        kwargs = {
            'scan_history_id': scan_id,
            'domain_id': domain.id,
            'engine_id': engine.id,
            'scan_type': LIVE_SCAN,
            'results_dir': SCAN_RESULTS_DIR,
            'imported_subdomains': imported,
            'out_of_scope_subdomains': out_of_scope,
            'starting_point_path': starting_point_path,
            'excluded_paths': excluded_paths,
            'initiated_by_id': user.id,
        }
        # Enqueue only after the ScanHistory row is committed, otherwise the worker can't see it.
        transaction.on_commit(lambda: initiate_scan.apply_async(kwargs=kwargs))
    scan = ScanHistory.objects.select_related('domain__project', 'scan_type', 'initiated_by').get(pk=scan_id)
    return scan, link


def _revoke(task_ids):
    from reNgine.celery import app
    for task_id in task_ids or []:
        try:
            app.control.revoke(task_id, terminate=True, signal='SIGKILL')
        except Exception:
            logger.exception('Failed to revoke celery task %s', task_id)


def stop_scan(user, scan):
    """Mirrors api.views.StopScan.abort_scan."""
    from reNgine.tasks import create_scan_activity

    if scan.scan_status not in ACTIVE_STATUSES:
        raise ApiError('scan is not running', status=409)
    scan.scan_status = ABORTED_TASK
    scan.stop_scan_date = timezone.now()
    scan.aborted_by = user
    scan.save()
    _revoke(scan.celery_ids)
    for task in ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK):
        task.status = ABORTED_TASK
        task.time = timezone.now()
        task.save()
    create_scan_activity(scan.id, 'Scan aborted', ABORTED_TASK)
    return scan


def stop_subscan(subscan):
    from reNgine.tasks import create_scan_activity

    if subscan.status not in ACTIVE_STATUSES:
        raise ApiError('subscan is not running', status=409)
    _revoke(subscan.celery_ids)
    subscan.status = ABORTED_TASK
    subscan.stop_scan_date = timezone.now()
    subscan.save()
    create_scan_activity(subscan.scan_history_id, 'Subscan aborted', ABORTED_TASK)
    return subscan


def _safe_results_dir(path):
    if not path:
        return None
    real = os.path.realpath(path)
    for root in RESULTS_ROOTS:
        root_real = os.path.realpath(root)
        if real != root_real and os.path.commonpath([real, root_real]) == root_real:
            return real
    return None


def delete_scan(scan):
    if scan.scan_status in ACTIVE_STATUSES:
        raise ApiError('scan is running; stop it first', status=409)
    if SubScan.objects.filter(scan_history=scan, status__in=ACTIVE_STATUSES).exists():
        raise ApiError('scan has running subscans; stop them first', status=409)
    results_dir = _safe_results_dir(scan.results_dir)
    scan.delete()
    if results_dir and os.path.isdir(results_dir):
        shutil.rmtree(results_dir, ignore_errors=True)


def scan_progress(scan):
    """Best-effort progress from ScanActivity rows vs engine tasks."""
    activities = list(ScanActivity.objects.filter(scan_of=scan).only('name', 'status'))
    engine_tasks = [t for t in (scan.tasks or []) if t in ENGINE_TASKS] or \
        [t for t in (scan.scan_type.tasks or []) if t in ENGINE_TASKS]
    finished = {a.name for a in activities if a.status not in ACTIVE_STATUSES}
    running = sorted({a.name for a in activities if a.status == RUNNING_TASK})
    done = len([t for t in engine_tasks if t in finished])
    total = len(engine_tasks)
    if scan.scan_status == SUCCESS_TASK:
        percent = 100
    elif total:
        percent = min(99, int(done * 100 / total)) if scan.scan_status in ACTIVE_STATUSES else int(done * 100 / total)
    else:
        percent = 0
    return {
        'percent': percent,
        'completed_tasks': done,
        'total_tasks': total,
        'running_tasks': running,
    }


MAX_RESULT_FILE_BYTES = 50 * 1024 * 1024


def read_port_scan_results(results_dir, scan_id, subscan_id=None):
    """Per-scan open ports from naabu's JSON output (`#<scan>[-<subscan>]_port_scan.txt`).

    reNgine's IpAddress/Port tables are global and only ever grow, so they cannot tell which
    ports were open *in this scan*. The task's own output file can. Returns (available, rows).
    """
    base = _safe_results_dir(results_dir)
    if not base:
        return False, []
    name = f'#{scan_id}-{subscan_id}_port_scan.txt' if subscan_id else f'#{scan_id}_port_scan.txt'
    path = os.path.realpath(os.path.join(base, name))
    if os.path.dirname(path) != base or not os.path.isfile(path):
        return False, []
    if os.path.getsize(path) > MAX_RESULT_FILE_BYTES:
        raise ApiError('port scan output is too large to serve', status=413)
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        logger.exception('Unreadable port scan output %s', path)
        return False, []
    rows = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get('port') or 0)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        host = str(item.get('host') or item.get('ip') or '').lower()
        ip = str(item.get('ip') or '')
        protocol = str(item.get('protocol') or 'tcp')
        rows[(host, ip, port, protocol)] = {
            'host': host, 'ip': ip, 'port': port, 'protocol': protocol, 'tls': bool(item.get('tls')),
        }
    return True, [rows[k] for k in sorted(rows)]


# ---------------------------------------------------------------- subscans

def start_subscans(user, data):
    from reNgine.tasks import initiate_subscan

    ids = data.get('subdomain_ids')
    if not isinstance(ids, list) or not ids:
        raise ApiError('subdomain_ids must be a non-empty list', field='subdomain_ids')
    try:
        ids = list(dict.fromkeys(int(i) for i in ids))
    except (TypeError, ValueError):
        raise ApiError('subdomain_ids must be integers', field='subdomain_ids')
    if len(ids) > 500:
        raise ApiError('too many subdomain_ids (max 500)', field='subdomain_ids')

    tasks = data.get('tasks')
    if not isinstance(tasks, list) or not tasks:
        raise ApiError('tasks must be a non-empty list', field='tasks')
    invalid = [t for t in tasks if t not in SUBSCAN_TASKS]
    if invalid:
        raise ApiError(f'unsupported subscan tasks: {invalid}; allowed: {list(SUBSCAN_TASKS)}', field='tasks')
    tasks = list(dict.fromkeys(tasks))

    engine_id = data.get('engine_id')
    if engine_id is not None:
        try:
            engine_id = int(engine_id)
        except (TypeError, ValueError):
            raise ApiError('engine_id must be an integer', field='engine_id')
        if not EngineType.objects.filter(pk=engine_id).exists():
            raise ApiError('engine not found', status=404, field='engine_id')

    subdomains = {s.id: s for s in Subdomain.objects.filter(pk__in=ids).select_related('scan_history')}
    missing = [i for i in ids if i not in subdomains]
    if missing:
        raise ApiError(f'subdomains not found: {missing[:20]}', status=404, field='subdomain_ids')
    orphan = [i for i, s in subdomains.items() if not s.scan_history_id]
    if orphan:
        raise ApiError(f'subdomains have no scan history: {orphan[:20]}', field='subdomain_ids')

    callback_url = validate_callback_url(data.get('callback_url'))
    external_ref = _external_ref(data.get('external_ref'))

    # The task id is generated up front and the link row is committed before the task is
    # enqueued, so the SubScan post_save signal can always bind to its link.
    requests_out = []
    jobs = []
    with transaction.atomic():
        for sid in ids:
            for task in tasks:
                task_id = str(uuid.uuid4())
                PentyScanLink.objects.create(
                    kind=PentyScanLink.KIND_SUBSCAN,
                    scan_history_id=subdomains[sid].scan_history_id,
                    celery_task_id=task_id,
                    subdomain_id=sid,
                    task=task,
                    external_ref=external_ref,
                    callback_url=callback_url,
                    created_by=user,
                )
                jobs.append((task_id, {
                    'scan_history_id': None,
                    'subdomain_id': sid,
                    'scan_type': task,
                    'engine_id': engine_id,
                }))
                requests_out.append({'subdomain_id': sid, 'task': task, 'celery_task_id': task_id})

        def _enqueue():
            for task_id, kwargs in jobs:
                initiate_subscan.apply_async(kwargs=kwargs, task_id=task_id)
        transaction.on_commit(_enqueue)
    return requests_out
