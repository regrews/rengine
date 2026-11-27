import logging

from django.conf import settings
from django.db import connection
from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework import status as http
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.models import Project
from penty_api import serializers as ser
from penty_api import services
from penty_api.auth import HasRenginePermission, PentyTokenAuthentication
from penty_api.constants import (
    ACTIVE_STATUSES, ENGINE_TASKS, SCAN_STATUS_NAMES, SUBSCAN_TASKS, VULNERABILITY_SCAN_TOOLS,
)
from penty_api.models import PentyScanLink
from penty_api.pagination import PentyPagination
from penty_api.services import ApiError
from reNgine.definitions import (
    PERM_INITATE_SCANS_SUBSCANS, PERM_MODIFY_SCAN_CONFIGURATIONS, PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_TARGETS,
)
from scanEngine.models import EngineType, InstalledExternalTool
from startScan.models import EndPoint, ScanActivity, ScanHistory, SubScan, Subdomain, Vulnerability
from targetApp.models import Domain

logger = logging.getLogger(__name__)


class PentyAPIView(APIView):
    authentication_classes = [PentyTokenAuthentication]
    permission_classes = [HasRenginePermission]
    renderer_classes = [JSONRenderer]
    parser_classes = [JSONParser]
    permission_required = None
    # Exempt from login_required.middleware (session redirect); auth is the Bearer token above.
    login_required = False

    def handle_exception(self, exc):
        if isinstance(exc, ApiError):
            body = {'error': exc.message}
            if exc.field:
                body['field'] = exc.field
            return Response(body, status=exc.status)
        return super().handle_exception(exc)

    def paginate(self, request, queryset, to_dict):
        paginator = PentyPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response([to_dict(o) for o in page])


def _int_param(request, name):
    value = request.query_params.get(name)
    if value in (None, ''):
        return None
    try:
        return int(value)
    except ValueError:
        raise ApiError(f'{name} must be an integer', field=name)


def _bool_param(request, name, default):
    value = request.query_params.get(name)
    if value is None:
        return default
    return value.lower() in ('1', 'true', 'yes')


def _scan_queryset():
    return ScanHistory.objects.select_related('domain__project', 'scan_type', 'initiated_by')


def _link_for_scan(scan_id):
    return PentyScanLink.objects.filter(kind=PentyScanLink.KIND_SCAN, scan_history_id=scan_id).first()


# ------------------------------------------------------------------ system

class HealthView(PentyAPIView):
    def get(self, request):
        db_ok = True
        try:
            with connection.cursor() as cur:
                cur.execute('SELECT 1')
        except Exception:
            db_ok = False

        workers = None
        try:
            from reNgine.celery import app
            replies = app.control.inspect(timeout=1.5).ping() or {}
            workers = sorted(replies.keys())
        except Exception:
            logger.exception('Celery ping failed')

        return Response({
            'status': 'ok' if db_ok and workers else 'degraded',
            'rengine_version': getattr(settings, 'RENGINE_CURRENT_VERSION', None),
            'api_version': 1,
            'database': db_ok,
            'celery_workers': workers,
            'active_scans': ScanHistory.objects.filter(scan_status__in=ACTIVE_STATUSES).count(),
            'active_subscans': SubScan.objects.filter(status__in=ACTIVE_STATUSES).count(),
            'user': request.user.username,
        })


class TasksCatalogView(PentyAPIView):
    def get(self, request):
        subdomain_tools = list(
            InstalledExternalTool.objects.filter(is_subdomain_gathering=True)
            .order_by('name').values_list('name', flat=True))
        return Response({
            'engine_tasks': [{'name': k, 'description': v, 'subscan': k in SUBSCAN_TASKS}
                             for k, v in ENGINE_TASKS.items()],
            'subscan_tasks': list(SUBSCAN_TASKS),
            'subdomain_discovery_tools': subdomain_tools,
            'vulnerability_scan_tools': list(VULNERABILITY_SCAN_TOOLS),
            'scan_statuses': SCAN_STATUS_NAMES,
        })


# ------------------------------------------------------------------ projects

class ProjectListView(PentyAPIView):
    permission_required = {'POST': PERM_MODIFY_TARGETS}

    def get(self, request):
        return Response([ser.project_dict(p) for p in Project.objects.order_by('id')])

    def post(self, request):
        project, created = services.create_project(request.data.get('name'))
        return Response(ser.project_dict(project), status=http.HTTP_201_CREATED if created else http.HTTP_200_OK)


# ------------------------------------------------------------------ targets

class TargetListView(PentyAPIView):
    permission_required = {'POST': PERM_MODIFY_TARGETS}

    def get(self, request):
        qs = Domain.objects.select_related('project').order_by('id')
        slug = request.query_params.get('project_slug')
        if slug:
            qs = qs.filter(project__slug=slug)
        search = request.query_params.get('search')
        if search:
            qs = qs.filter(name__icontains=search)
        return self.paginate(request, qs, ser.target_dict)

    def post(self, request):
        domain, created = services.create_target(
            request.data.get('project_slug'), request.data.get('name'), request.data.get('description'))
        domain = Domain.objects.select_related('project').get(pk=domain.pk)
        return Response(ser.target_dict(domain), status=http.HTTP_201_CREATED if created else http.HTTP_200_OK)


class TargetDetailView(PentyAPIView):
    permission_required = {'PATCH': PERM_MODIFY_TARGETS, 'DELETE': PERM_MODIFY_TARGETS}

    def get_object(self, pk):
        return get_object_or_404(Domain.objects.select_related('project'), pk=pk)

    def get(self, request, pk):
        return Response(ser.target_dict(self.get_object(pk)))

    def patch(self, request, pk):
        domain = self.get_object(pk)
        if 'description' in request.data:
            desc = request.data.get('description') or ''
            if not isinstance(desc, str):
                raise ApiError('description must be a string', field='description')
            domain.description = desc[:5000]
            domain.save(update_fields=['description'])
        return Response(ser.target_dict(domain))

    def delete(self, request, pk):
        services.delete_target(self.get_object(pk))
        return Response(status=http.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ engines

class EngineListView(PentyAPIView):
    permission_required = {'POST': PERM_MODIFY_SCAN_CONFIGURATIONS}

    def get(self, request):
        engines = EngineType.objects.annotate(n=Count('scanhistory')).order_by('id')
        return Response([ser.engine_dict(e, scan_count=e.n) for e in engines])

    def post(self, request):
        engine = services.create_engine(request.data.get('name'), request.data.get('yaml_configuration'))
        return Response(ser.engine_dict(engine, include_yaml=True), status=http.HTTP_201_CREATED)


class EngineDetailView(PentyAPIView):
    permission_required = {
        'PUT': PERM_MODIFY_SCAN_CONFIGURATIONS,
        'PATCH': PERM_MODIFY_SCAN_CONFIGURATIONS,
        'DELETE': PERM_MODIFY_SCAN_CONFIGURATIONS,
    }

    def get(self, request, pk):
        return Response(ser.engine_dict(get_object_or_404(EngineType, pk=pk), include_yaml=True))

    def put(self, request, pk):
        engine = get_object_or_404(EngineType, pk=pk)
        engine = services.update_engine(
            engine, request.data.get('name'), request.data.get('yaml_configuration'))
        return Response(ser.engine_dict(engine, include_yaml=True))

    patch = put

    def delete(self, request, pk):
        services.delete_engine(get_object_or_404(EngineType, pk=pk))
        return Response(status=http.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ scans

class ScanListView(PentyAPIView):
    permission_required = {'POST': PERM_INITATE_SCANS_SUBSCANS}

    def get(self, request):
        qs = _scan_queryset().order_by('-id')
        target_id = _int_param(request, 'target_id')
        if target_id is not None:
            qs = qs.filter(domain_id=target_id)
        slug = request.query_params.get('project_slug')
        if slug:
            qs = qs.filter(domain__project__slug=slug)
        status_value = _int_param(request, 'status')
        if status_value is not None:
            qs = qs.filter(scan_status=status_value)
        ref = request.query_params.get('external_ref')
        if ref:
            qs = qs.filter(penty_links__external_ref=ref).distinct()
        return self.paginate(request, qs, ser.scan_dict)

    def post(self, request):
        scan, link = services.start_scan(request.user, request.data)
        return Response(ser.scan_dict(scan, link=link), status=http.HTTP_201_CREATED)


class ScanDetailView(PentyAPIView):
    permission_required = {'DELETE': PERM_MODIFY_SCAN_RESULTS}

    def get(self, request, pk):
        scan = get_object_or_404(_scan_queryset(), pk=pk)
        data = ser.scan_dict(scan, progress=services.scan_progress(scan), link=_link_for_scan(scan.id))
        data['counts'] = {
            'subdomains': Subdomain.objects.filter(scan_history=scan).count(),
            'endpoints': EndPoint.objects.filter(scan_history=scan).count(),
            'vulnerabilities': Vulnerability.objects.filter(scan_history=scan).count(),
            'subscans': SubScan.objects.filter(scan_history=scan).count(),
        }
        return Response(data)

    def delete(self, request, pk):
        services.delete_scan(get_object_or_404(ScanHistory, pk=pk))
        return Response(status=http.HTTP_204_NO_CONTENT)


class ScanStopView(PentyAPIView):
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        scan = services.stop_scan(request.user, get_object_or_404(_scan_queryset(), pk=pk))
        return Response(ser.scan_dict(scan))


class ScanActivityView(PentyAPIView):
    def get(self, request, pk):
        scan = get_object_or_404(ScanHistory, pk=pk)
        qs = ScanActivity.objects.filter(scan_of=scan).order_by('id')
        return self.paginate(request, qs, ser.activity_dict)


# ------------------------------------------------------------------ results

def _vuln_qs():
    return (
        Vulnerability.objects
        .select_related('subdomain')
        .prefetch_related('cve_ids', 'cwe_ids', 'tags', 'references')
        .order_by('id')
    )


def _subdomain_qs():
    return (
        Subdomain.objects
        .prefetch_related('technologies', 'waf', 'ip_addresses__ports')
        .order_by('id')
    )


def _endpoint_qs():
    return EndPoint.objects.prefetch_related('techs').order_by('id')


class _ResultsMixin:
    def vulnerabilities(self, request, qs):
        min_sev = _int_param(request, 'severity_min')
        if min_sev is not None:
            qs = qs.filter(severity__gte=min_sev)
        include_http = _bool_param(request, 'include_http', True)
        return self.paginate(request, qs, lambda v: ser.vulnerability_dict(v, include_http=include_http))

    def ports(self, request, available, rows):
        response = self.paginate(request, rows, lambda r: r)
        response.data['available'] = available
        return response


class ScanResultsView(_ResultsMixin, PentyAPIView):
    KINDS = ('vulnerabilities', 'subdomains', 'endpoints', 'ports')

    def get(self, request, pk, kind):
        if kind not in self.KINDS:
            raise ApiError(f'unknown result type; use one of {list(self.KINDS)}', status=404)
        scan = get_object_or_404(ScanHistory, pk=pk)
        if kind == 'ports':
            return self.ports(request, *services.read_port_scan_results(scan.results_dir, scan.id))
        if kind == 'vulnerabilities':
            return self.vulnerabilities(request, _vuln_qs().filter(scan_history=scan))
        if kind == 'subdomains':
            qs = _subdomain_qs().filter(scan_history=scan)
            if _bool_param(request, 'alive_only', False):
                qs = qs.filter(http_status__gt=0)
            return self.paginate(request, qs, ser.subdomain_dict)
        qs = _endpoint_qs().filter(scan_history=scan)
        return self.paginate(request, qs, ser.endpoint_dict)


# ------------------------------------------------------------------ subscans

def _subscan_qs():
    return SubScan.objects.select_related('subdomain')


class SubscanListView(PentyAPIView):
    permission_required = {'POST': PERM_INITATE_SCANS_SUBSCANS}

    def get(self, request):
        qs = _subscan_qs().order_by('-id')
        scan_id = _int_param(request, 'scan_id')
        if scan_id is not None:
            qs = qs.filter(scan_history_id=scan_id)
        celery_task_id = request.query_params.get('celery_task_id')
        if celery_task_id:
            qs = qs.filter(celery_ids__contains=[celery_task_id])
        ref = request.query_params.get('external_ref')
        if ref:
            qs = qs.filter(penty_links__external_ref=ref).distinct()
        return self.paginate(request, qs, ser.subscan_dict)

    def post(self, request):
        queued = services.start_subscans(request.user, request.data)
        return Response({'queued': queued}, status=http.HTTP_202_ACCEPTED)


class SubscanDetailView(PentyAPIView):
    def get(self, request, pk):
        sub = get_object_or_404(_subscan_qs(), pk=pk)
        link = PentyScanLink.objects.filter(kind=PentyScanLink.KIND_SUBSCAN, subscan=sub).first()
        return Response(ser.subscan_dict(sub, link=link))


class SubscanStopView(PentyAPIView):
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        sub = services.stop_subscan(get_object_or_404(_subscan_qs(), pk=pk))
        return Response(ser.subscan_dict(sub))


class SubscanResultsView(_ResultsMixin, PentyAPIView):
    KINDS = ('vulnerabilities', 'subdomains', 'endpoints', 'ports')

    def get(self, request, pk, kind):
        if kind not in self.KINDS:
            raise ApiError(f'unknown result type; use one of {list(self.KINDS)}', status=404)
        sub = get_object_or_404(SubScan.objects.select_related('scan_history'), pk=pk)
        if kind == 'ports':
            results_dir = f'{sub.scan_history.results_dir}/subscans/{sub.id}' if sub.scan_history.results_dir else ''
            return self.ports(request, *services.read_port_scan_results(results_dir, sub.scan_history_id, sub.id))
        if kind == 'vulnerabilities':
            return self.vulnerabilities(request, _vuln_qs().filter(vuln_subscan_ids=sub))
        if kind == 'subdomains':
            return self.paginate(request, _subdomain_qs().filter(pk=sub.subdomain_id), ser.subdomain_dict)
        return self.paginate(request, _endpoint_qs().filter(endpoint_subscan_ids=sub), ser.endpoint_dict)
