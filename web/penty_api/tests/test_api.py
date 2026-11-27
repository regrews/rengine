import json
import os
import shutil
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from penty_api import services, webhook
from penty_api.models import PentyApiToken, PentyIntegrationConfig, PentyScanLink
from reNgine.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import (
    CveId, IpAddress, Port, ScanActivity, ScanHistory, SubScan, Subdomain, Technology,
    Vulnerability, VulnerabilityTags,
)
from targetApp.models import Domain

BASE = '/api/v1/penty'

RECON_YAML = """subdomain_discovery: {
  uses_tools: [subfinder],
  threads: 10,
}
http_crawl: {
  threads: 10,
}
port_scan: {
  ports: [top-100],
}
"""


class Fixture(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('penty-service', password='x')
        assign_role(self.user, 'penetration_tester')
        self.token, self.raw = PentyApiToken.issue(self.user, 'test')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.raw}')

        self.project = Project.objects.create(name='CyberWhiz', slug='cyberwhiz', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='cyberwhiz.co.uk', project=self.project, insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='Penty-Recon', yaml_configuration=RECON_YAML)
        self.default_engine = EngineType.objects.create(
            engine_name='Builtin', yaml_configuration=RECON_YAML, default_engine=True)

    def make_scan(self, status=SUCCESS_TASK, results_dir=''):
        return ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine, scan_status=status,
            start_scan_date=timezone.now(), results_dir=results_dir,
            tasks=['subdomain_discovery', 'http_crawl', 'port_scan'])

    def post(self, url, data=None):
        return self.client.post(BASE + url, data=json.dumps(data or {}), content_type='application/json')


# ---------------------------------------------------------------- auth

@mock.patch('reNgine.celery.app.control.inspect')
class AuthTests(Fixture):
    def test_missing_token_is_401_not_login_redirect(self, _inspect):
        resp = APIClient().get(f'{BASE}/health/')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('Bearer', resp['WWW-Authenticate'])

    def test_invalid_token_is_401(self, _inspect):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION='Bearer rgp_nope')
        self.assertEqual(c.get(f'{BASE}/health/').status_code, 401)

    def test_revoked_token_is_401(self, _inspect):
        self.token.revoked_at = timezone.now()
        self.token.save()
        self.assertEqual(self.client.get(f'{BASE}/health/').status_code, 401)

    def test_inactive_user_is_401(self, _inspect):
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.client.get(f'{BASE}/health/').status_code, 401)

    def test_session_login_is_not_accepted(self, _inspect):
        # Build an authenticated Django session by hand (reNgine's user_logged_in receiver
        # breaks Client.force_login) and make sure the API still demands a Bearer token.
        from django.contrib.sessions.backends.db import SessionStore
        session = SessionStore()
        session['_auth_user_id'] = str(self.user.pk)
        session['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
        session['_auth_user_hash'] = self.user.get_session_auth_hash()
        session.create()
        c = APIClient()
        c.cookies['sessionid'] = session.session_key
        self.assertEqual(c.get(f'{BASE}/health/').status_code, 401)
        c.credentials(HTTP_AUTHORIZATION='Basic ' + __import__('base64').b64encode(b'penty-service:x').decode())
        self.assertEqual(c.get(f'{BASE}/health/').status_code, 401)

    def test_valid_token_health(self, inspect):
        inspect.return_value.ping.return_value = {'celery@w1': {'ok': 'pong'}}
        resp = self.client.get(f'{BASE}/health/')
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body['status'], 'ok')
        self.assertEqual(body['celery_workers'], ['celery@w1'])
        self.assertTrue(body['database'])
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)

    def test_only_hash_is_stored(self, _inspect):
        self.assertNotEqual(self.token.key_hash, self.raw)
        self.assertEqual(len(self.token.key_hash), 64)
        self.assertTrue(self.raw.startswith('rgp_'))

    def test_auditor_cannot_start_scan_but_can_read(self, _inspect):
        auditor = User.objects.create_user('aud', password='x')
        assign_role(auditor, 'auditor')
        _, raw = PentyApiToken.issue(auditor, 'aud')
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f'Bearer {raw}')
        self.assertEqual(c.get(f'{BASE}/scans/').status_code, 200)
        resp = c.post(f'{BASE}/scans/', data=json.dumps({'target_id': self.domain.id, 'engine_id': self.engine.id}),
                      content_type='application/json')
        self.assertEqual(resp.status_code, 403)


# ---------------------------------------------------------------- projects & targets

class ProjectTargetTests(Fixture):
    def test_create_project_idempotent(self):
        r1 = self.post('/projects/', {'name': 'Acme Corp'})
        self.assertEqual(r1.status_code, 201)
        self.assertEqual(r1.json()['slug'], 'acme-corp')
        r2 = self.post('/projects/', {'name': 'Acme Corp'})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(Project.objects.filter(slug='acme-corp').count(), 1)

    def test_create_project_invalid(self):
        self.assertEqual(self.post('/projects/', {'name': '  '}).status_code, 400)
        self.assertEqual(self.post('/projects/', {'name': '!!!'}).status_code, 400)

    def test_create_domain_target_and_idempotency(self):
        r = self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': 'App.CyberWhiz-Test.co.uk.'})
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()['name'], 'app.cyberwhiz-test.co.uk')
        self.assertEqual(r.json()['project_slug'], 'cyberwhiz')
        r2 = self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': 'app.cyberwhiz-test.co.uk'})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()['id'], r.json()['id'])

    def test_wildcard_is_stripped(self):
        r = self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': '*.wild-example.co.uk'})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['name'], 'wild-example.co.uk')

    def test_target_in_other_project_conflicts(self):
        Project.objects.create(name='Other', slug='other', insert_date=timezone.now())
        r = self.post('/targets/', {'project_slug': 'other', 'name': 'cyberwhiz.co.uk'})
        self.assertEqual(r.status_code, 409)

    def test_cidr_and_garbage_rejected(self):
        r = self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': '10.0.0.0/24'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('CIDR', r.json()['error'])
        self.assertEqual(self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': 'not a host'}).status_code, 400)

    def test_unknown_project_404(self):
        self.assertEqual(self.post('/targets/', {'project_slug': 'nope', 'name': 'x-example.com'}).status_code, 404)

    @mock.patch('reNgine.database_utils.get_ip_info')
    def test_ip_target(self, ip_info):
        ip_info.return_value = mock.Mock(reverse_pointer='1.2.0.192.in-addr.arpa', is_private=False, version=4)
        r = self.post('/targets/', {'project_slug': 'cyberwhiz', 'name': '192.0.2.1'})
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()['ip_address_cidr'], '192.0.2.1')

    def test_list_filter_patch_delete(self):
        other = Project.objects.create(name='Other', slug='other', insert_date=timezone.now())
        Domain.objects.create(name='other-example.com', project=other, insert_date=timezone.now())
        r = self.client.get(f'{BASE}/targets/?project_slug=cyberwhiz')
        self.assertEqual(r.json()['count'], 1)
        self.assertEqual(r.json()['results'][0]['name'], 'cyberwhiz.co.uk')

        r = self.client.patch(f'{BASE}/targets/{self.domain.id}/', data=json.dumps({'description': 'main'}),
                              content_type='application/json')
        self.assertEqual(r.json()['description'], 'main')

        self.make_scan(status=RUNNING_TASK)
        self.assertEqual(self.client.delete(f'{BASE}/targets/{self.domain.id}/').status_code, 409)


# ---------------------------------------------------------------- engines

class EngineTests(Fixture):
    def test_create_and_get(self):
        r = self.post('/engines/', {'name': 'Penty-Nuclei', 'yaml_configuration': 'vulnerability_scan: {run_nuclei: true}\n'})
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()['tasks'], ['vulnerability_scan'])
        self.assertFalse(r.json()['is_default'])
        g = self.client.get(f'{BASE}/engines/{r.json()["id"]}/')
        self.assertIn('run_nuclei', g.json()['yaml_configuration'])

    def test_list_has_tasks_and_counts(self):
        self.make_scan()
        engines = {e['name']: e for e in self.client.get(f'{BASE}/engines/').json()}
        self.assertEqual(engines['Penty-Recon']['tasks'], ['subdomain_discovery', 'http_crawl', 'port_scan'])
        self.assertEqual(engines['Penty-Recon']['scan_count'], 1)

    def test_yaml_validation(self):
        cases = ['', 'not: [valid', '- a\n- b\n', 'foo: {a: 1}\n', 'port_scan: 5\n']
        for y in cases:
            r = self.post('/engines/', {'name': f'E{len(y)}', 'yaml_configuration': y})
            self.assertEqual(r.status_code, 400, (y, r.content))

    def test_duplicate_name_conflict(self):
        r = self.post('/engines/', {'name': 'penty-recon', 'yaml_configuration': RECON_YAML})
        self.assertEqual(r.status_code, 409)

    def test_builtin_engine_is_read_only(self):
        url = f'{BASE}/engines/{self.default_engine.id}/'
        r = self.client.put(url, data=json.dumps({'name': 'x'}), content_type='application/json')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.delete(url).status_code, 403)

    def test_update_engine(self):
        r = self.client.put(f'{BASE}/engines/{self.engine.id}/',
                            data=json.dumps({'yaml_configuration': 'port_scan: {ports: [top-1000]}\n'}),
                            content_type='application/json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()['tasks'], ['port_scan'])
        self.assertEqual(r.json()['name'], 'Penty-Recon')

    def test_used_engine_cannot_be_deleted(self):
        self.make_scan()
        self.assertEqual(self.client.delete(f'{BASE}/engines/{self.engine.id}/').status_code, 409)
        self.assertTrue(ScanHistory.objects.exists())

    def test_unused_engine_deleted(self):
        self.assertEqual(self.client.delete(f'{BASE}/engines/{self.engine.id}/').status_code, 204)
        self.assertFalse(EngineType.objects.filter(pk=self.engine.id).exists())


# ---------------------------------------------------------------- scans

class ScanTests(Fixture):
    @mock.patch('reNgine.tasks.initiate_scan.apply_async')
    def test_start_scan(self, apply_async):
        payload = {
            'target_id': self.domain.id, 'engine_id': self.engine.id,
            'imported_subdomains': ['WWW.cyberwhiz.co.uk', 'www.cyberwhiz.co.uk', ' '],
            'out_of_scope_subdomains': 'mail.cyberwhiz.co.uk, vpn.cyberwhiz.co.uk',
            'starting_point_path': '/app', 'excluded_paths': ['/logout'],
            'external_ref': 'penty-run-1',
        }
        with self.captureOnCommitCallbacks(execute=True):
            r = self.post('/scans/', payload)
        self.assertEqual(r.status_code, 201, r.content)
        body = r.json()
        self.assertEqual(body['status'], INITIATED_TASK)
        self.assertEqual(body['status_name'], 'initiated')
        self.assertEqual(body['penty']['external_ref'], 'penty-run-1')

        scan = ScanHistory.objects.get(pk=body['id'])
        self.assertEqual(scan.initiated_by, self.user)
        apply_async.assert_called_once()
        kwargs = apply_async.call_args.kwargs['kwargs']
        self.assertEqual(kwargs['scan_history_id'], scan.id)
        self.assertEqual(kwargs['domain_id'], self.domain.id)
        self.assertEqual(kwargs['engine_id'], self.engine.id)
        self.assertEqual(kwargs['imported_subdomains'], ['www.cyberwhiz.co.uk'])
        self.assertEqual(kwargs['out_of_scope_subdomains'], ['mail.cyberwhiz.co.uk', 'vpn.cyberwhiz.co.uk'])
        self.assertEqual(kwargs['starting_point_path'], '/app')
        self.assertEqual(kwargs['excluded_paths'], ['/logout'])
        self.assertEqual(kwargs['results_dir'], '/usr/src/scan_results')
        self.assertEqual(kwargs['initiated_by_id'], self.user.id)
        self.assertTrue(PentyScanLink.objects.filter(scan_history=scan, external_ref='penty-run-1').exists())

    @mock.patch('reNgine.tasks.initiate_scan.apply_async')
    def test_start_scan_validation(self, apply_async):
        bad = [
            ({'engine_id': self.engine.id}, 400),
            ({'target_id': 999999, 'engine_id': self.engine.id}, 404),
            ({'target_id': self.domain.id, 'engine_id': 999999}, 404),
            ({'target_id': self.domain.id, 'engine_id': self.engine.id, 'starting_point_path': 'app'}, 400),
            ({'target_id': self.domain.id, 'engine_id': self.engine.id, 'imported_subdomains': [1, 2]}, 400),
            ({'target_id': self.domain.id, 'engine_id': self.engine.id, 'callback_url': 'ftp://x'}, 400),
        ]
        for payload, code in bad:
            self.assertEqual(self.post('/scans/', payload).status_code, code, payload)
        self.assertFalse(ScanHistory.objects.exists())
        apply_async.assert_not_called()

    @mock.patch('reNgine.tasks.initiate_scan.apply_async')
    def test_callback_prefix_enforced(self, _apply):
        cfg = PentyIntegrationConfig.get()
        cfg.allowed_callback_prefix = 'https://penty.internal/'
        cfg.save()
        base = {'target_id': self.domain.id, 'engine_id': self.engine.id}
        self.assertEqual(self.post('/scans/', {**base, 'callback_url': 'https://evil.example/x'}).status_code, 400)
        self.assertEqual(
            self.post('/scans/', {**base, 'callback_url': 'https://penty.internal/api/hook'}).status_code, 201)

    def test_list_and_filters(self):
        s1 = self.make_scan(SUCCESS_TASK)
        s2 = self.make_scan(RUNNING_TASK)
        PentyScanLink.objects.create(kind='scan', scan_history=s2, external_ref='ref-2')
        r = self.client.get(f'{BASE}/scans/?project_slug=cyberwhiz')
        self.assertEqual([s['id'] for s in r.json()['results']], [s2.id, s1.id])
        r = self.client.get(f'{BASE}/scans/?status={SUCCESS_TASK}')
        self.assertEqual([s['id'] for s in r.json()['results']], [s1.id])
        r = self.client.get(f'{BASE}/scans/?external_ref=ref-2')
        self.assertEqual([s['id'] for s in r.json()['results']], [s2.id])
        self.assertEqual(self.client.get(f'{BASE}/scans/?status=abc').status_code, 400)

    def test_detail_progress(self):
        scan = self.make_scan(RUNNING_TASK)
        now = timezone.now()
        ScanActivity.objects.create(scan_of=scan, name='subdomain_discovery', title='x', time=now, status=SUCCESS_TASK)
        ScanActivity.objects.create(scan_of=scan, name='http_crawl', title='x', time=now, status=RUNNING_TASK)
        body = self.client.get(f'{BASE}/scans/{scan.id}/').json()
        self.assertEqual(body['progress']['completed_tasks'], 1)
        self.assertEqual(body['progress']['total_tasks'], 3)
        self.assertEqual(body['progress']['percent'], 50)  # 1 done + 1 running (half) of 3
        self.assertEqual(body['progress']['running_tasks'], ['http_crawl'])
        self.assertEqual(body['counts']['vulnerabilities'], 0)

        scan.scan_status = SUCCESS_TASK
        scan.save()
        self.assertEqual(self.client.get(f'{BASE}/scans/{scan.id}/').json()['progress']['percent'], 100)

    def test_activity_list(self):
        scan = self.make_scan()
        ScanActivity.objects.create(scan_of=scan, name='port_scan', title='Port scan', time=timezone.now(), status=FAILED_TASK,
                                    error_message='boom')
        r = self.client.get(f'{BASE}/scans/{scan.id}/activity/').json()
        self.assertEqual(r['count'], 1)
        self.assertEqual(r['results'][0]['status_name'], 'failed')
        self.assertEqual(r['results'][0]['error_message'], 'boom')

    @mock.patch('reNgine.celery.app.control.revoke')
    def test_stop_scan(self, revoke):
        scan = self.make_scan(RUNNING_TASK)
        scan.celery_ids = ['c1', 'c2']
        scan.save()
        ScanActivity.objects.create(scan_of=scan, name='port_scan', title='x', time=timezone.now(), status=RUNNING_TASK)
        r = self.post(f'/scans/{scan.id}/stop/')
        self.assertEqual(r.status_code, 200, r.content)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED_TASK)
        self.assertEqual(scan.aborted_by, self.user)
        self.assertIsNotNone(scan.stop_scan_date)
        self.assertEqual(revoke.call_count, 2)
        self.assertFalse(ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).exists())
        self.assertTrue(ScanActivity.objects.filter(scan_of=scan, title='Scan aborted').exists())
        # stopping again is a conflict
        self.assertEqual(self.post(f'/scans/{scan.id}/stop/').status_code, 409)

    def test_delete_scan(self):
        root = tempfile.mkdtemp()
        results = os.path.join(root, 'cyberwhiz.co.uk_1')
        os.makedirs(results)
        with mock.patch('penty_api.services.RESULTS_ROOTS', (root,)):
            running = self.make_scan(RUNNING_TASK, results_dir=results)
            self.assertEqual(self.client.delete(f'{BASE}/scans/{running.id}/').status_code, 409)
            done = self.make_scan(SUCCESS_TASK, results_dir=results)
            self.assertEqual(self.client.delete(f'{BASE}/scans/{done.id}/').status_code, 204)
        self.assertFalse(ScanHistory.objects.filter(pk=done.id).exists())
        self.assertFalse(os.path.exists(results))
        shutil.rmtree(root, ignore_errors=True)

    def test_safe_results_dir(self):
        root = tempfile.mkdtemp()
        try:
            with mock.patch('penty_api.services.RESULTS_ROOTS', (root,)):
                self.assertIsNone(services._safe_results_dir('/etc'))
                self.assertIsNone(services._safe_results_dir(root))
                self.assertIsNone(services._safe_results_dir(os.path.join(root, '..')))
                self.assertIsNone(services._safe_results_dir(os.path.join(root, 'a', '..', '..', 'etc')))
                self.assertIsNone(services._safe_results_dir(''))
                self.assertEqual(services._safe_results_dir(os.path.join(root, 'x')),
                                 os.path.realpath(os.path.join(root, 'x')))
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------- results

class ResultTests(Fixture):
    def setUp(self):
        super().setUp()
        self.scan = self.make_scan()
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='www.cyberwhiz.co.uk',
            http_url='https://www.cyberwhiz.co.uk', http_status=200, page_title='Home', webserver='nginx')
        self.sub.technologies.add(Technology.objects.create(name='Nginx:1.18.0'), Technology.objects.create(name='WordPress'))
        ip = IpAddress.objects.create(address='192.0.2.10')
        ip.ports.add(Port.objects.create(number=443, service_name='https'), Port.objects.create(number=80, service_name='http'))
        self.sub.ip_addresses.add(ip)
        Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='dead.cyberwhiz.co.uk', http_status=0)

        self.v_high = Vulnerability.objects.create(
            scan_history=self.scan, subdomain=self.sub, target_domain=self.domain, name='Exposed .git', severity=3,
            template_id='git-config', matcher_name='', http_url='https://www.cyberwhiz.co.uk/.git/config',
            request='GET /.git/config', response='[core]', source='nuclei')
        self.v_high.cve_ids.add(CveId.objects.create(name='CVE-2020-1234'))
        self.v_high.tags.add(VulnerabilityTags.objects.create(name='exposure'))
        Vulnerability.objects.create(scan_history=self.scan, target_domain=self.domain, name='Info thing', severity=0)

    def test_vulnerabilities(self):
        r = self.client.get(f'{BASE}/scans/{self.scan.id}/results/vulnerabilities/').json()
        self.assertEqual(r['count'], 2)
        v = next(x for x in r['results'] if x['id'] == self.v_high.id)
        self.assertEqual(v['severity_name'], 'high')
        self.assertEqual(v['template_id'], 'git-config')
        self.assertEqual(v['cve_ids'], ['CVE-2020-1234'])
        self.assertEqual(v['tags'], ['exposure'])
        self.assertEqual(v['subdomain']['name'], 'www.cyberwhiz.co.uk')
        self.assertEqual(v['request'], 'GET /.git/config')

        r = self.client.get(f'{BASE}/scans/{self.scan.id}/results/vulnerabilities/?severity_min=1&include_http=0').json()
        self.assertEqual(r['count'], 1)
        self.assertNotIn('request', r['results'][0])

    def test_subdomains_with_tech_and_ports(self):
        r = self.client.get(f'{BASE}/scans/{self.scan.id}/results/subdomains/').json()
        self.assertEqual(r['count'], 2)
        s = next(x for x in r['results'] if x['name'] == 'www.cyberwhiz.co.uk')
        self.assertEqual(s['technologies'], ['Nginx:1.18.0', 'WordPress'])
        self.assertEqual([p['number'] for p in s['ip_addresses'][0]['ports']], [80, 443])
        r = self.client.get(f'{BASE}/scans/{self.scan.id}/results/subdomains/?alive_only=1').json()
        self.assertEqual(r['count'], 1)

    def test_pagination_and_unknown_kind(self):
        r = self.client.get(f'{BASE}/scans/{self.scan.id}/results/vulnerabilities/?page_size=1').json()
        self.assertEqual(r['count'], 2)
        self.assertEqual(len(r['results']), 1)
        self.assertIsNotNone(r['next'])
        self.assertEqual(self.client.get(f'{BASE}/scans/{self.scan.id}/results/screenshots/').status_code, 404)
        self.assertEqual(self.client.get(f'{BASE}/scans/999999/results/vulnerabilities/').status_code, 404)


class PortResultTests(Fixture):
    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.patcher = mock.patch('penty_api.services.RESULTS_ROOTS', (self.root,))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _write(self, path, rows):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(rows, f)

    def test_scan_ports_from_output_file(self):
        results = os.path.join(self.root, 'cyberwhiz.co.uk_9')
        scan = self.make_scan(results_dir=results)
        self._write(os.path.join(results, f'#{scan.id}_port_scan.txt'), [
            {'host': 'WWW.cyberwhiz.co.uk', 'ip': '192.0.2.1', 'port': 443, 'protocol': 'tcp', 'tls': True},
            {'host': 'www.cyberwhiz.co.uk', 'ip': '192.0.2.1', 'port': 443, 'protocol': 'tcp', 'tls': True},
            {'host': 'www.cyberwhiz.co.uk', 'ip': '192.0.2.1', 'port': 22, 'protocol': 'tcp'},
            {'host': 'x', 'ip': '192.0.2.2', 'port': 0},
            'garbage',
        ])
        r = self.client.get(f'{BASE}/scans/{scan.id}/results/ports/').json()
        self.assertTrue(r['available'])
        self.assertEqual(r['count'], 2)
        self.assertEqual([(x['host'], x['port']) for x in r['results']],
                         [('www.cyberwhiz.co.uk', 22), ('www.cyberwhiz.co.uk', 443)])
        self.assertTrue(r['results'][1]['tls'])

    def test_missing_or_unsafe_file(self):
        scan = self.make_scan(results_dir=os.path.join(self.root, 'none'))
        r = self.client.get(f'{BASE}/scans/{scan.id}/results/ports/').json()
        self.assertFalse(r['available'])
        self.assertEqual(r['count'], 0)
        outside = self.make_scan(results_dir='/etc')
        self.assertFalse(self.client.get(f'{BASE}/scans/{outside.id}/results/ports/').json()['available'])

    def test_subscan_ports(self):
        results = os.path.join(self.root, 'cyberwhiz.co.uk_10')
        scan = self.make_scan(results_dir=results)
        sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='www.cyberwhiz.co.uk')
        subscan = SubScan.objects.create(type='port_scan', start_scan_date=timezone.now(), status=SUCCESS_TASK,
                                         scan_history=scan, subdomain=sub)
        self._write(os.path.join(results, 'subscans', str(subscan.id), f'#{scan.id}-{subscan.id}_port_scan.txt'),
                    [{'host': 'www.cyberwhiz.co.uk', 'ip': '192.0.2.1', 'port': 8443, 'protocol': 'tcp'}])
        r = self.client.get(f'{BASE}/subscans/{subscan.id}/results/ports/').json()
        self.assertTrue(r['available'])
        self.assertEqual(r['results'][0]['port'], 8443)


# ---------------------------------------------------------------- subscans

class SubscanTests(Fixture):
    def setUp(self):
        super().setUp()
        self.scan = self.make_scan()
        self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='www.cyberwhiz.co.uk')

    @mock.patch('reNgine.tasks.initiate_subscan.apply_async')
    def test_start_subscans_links_before_enqueue(self, apply_async):
        with self.captureOnCommitCallbacks(execute=True):
            r = self.post('/subscans/', {'subdomain_ids': [self.sub.id], 'tasks': ['vulnerability_scan', 'port_scan'],
                                         'external_ref': 'retest-7'})
        self.assertEqual(r.status_code, 202, r.content)
        queued = r.json()['queued']
        self.assertEqual(len(queued), 2)
        self.assertEqual(apply_async.call_count, 2)
        for call, q in zip(apply_async.call_args_list, queued):
            self.assertEqual(call.kwargs['task_id'], q['celery_task_id'])
            self.assertEqual(call.kwargs['kwargs']['subdomain_id'], self.sub.id)
            self.assertEqual(call.kwargs['kwargs']['scan_type'], q['task'])
        self.assertEqual(PentyScanLink.objects.filter(kind='subscan', external_ref='retest-7').count(), 2)

    @mock.patch('reNgine.tasks.initiate_subscan.apply_async')
    def test_subscan_validation(self, apply_async):
        self.assertEqual(self.post('/subscans/', {'subdomain_ids': [self.sub.id], 'tasks': ['rm_rf']}).status_code, 400)
        self.assertEqual(self.post('/subscans/', {'subdomain_ids': [], 'tasks': ['port_scan']}).status_code, 400)
        self.assertEqual(self.post('/subscans/', {'subdomain_ids': [999999], 'tasks': ['port_scan']}).status_code, 404)
        self.assertEqual(self.post('/subscans/', {'subdomain_ids': [self.sub.id], 'tasks': ['port_scan'],
                                                  'engine_id': 999999}).status_code, 404)
        apply_async.assert_not_called()

    def test_subscan_row_binds_to_link_and_results(self):
        PentyScanLink.objects.create(kind='subscan', celery_task_id='celery-abc', subdomain_id=self.sub.id,
                                     task='vulnerability_scan', external_ref='retest-7')
        subscan = SubScan.objects.create(type='vulnerability_scan', start_scan_date=timezone.now(), status=RUNNING_TASK,
                                         scan_history=self.scan, subdomain=self.sub, engine=self.engine,
                                         celery_ids=['celery-abc'])
        link = PentyScanLink.objects.get(celery_task_id='celery-abc')
        self.assertEqual(link.subscan_id, subscan.id)

        v = Vulnerability.objects.create(scan_history=self.scan, subdomain=self.sub, name='XSS', severity=2)
        v.vuln_subscan_ids.add(subscan)
        Vulnerability.objects.create(scan_history=self.scan, subdomain=self.sub, name='Other', severity=2)

        r = self.client.get(f'{BASE}/subscans/?celery_task_id=celery-abc').json()
        self.assertEqual(r['results'][0]['id'], subscan.id)
        d = self.client.get(f'{BASE}/subscans/{subscan.id}/').json()
        self.assertEqual(d['penty']['external_ref'], 'retest-7')
        vulns = self.client.get(f'{BASE}/subscans/{subscan.id}/results/vulnerabilities/').json()
        self.assertEqual([x['name'] for x in vulns['results']], ['XSS'])

    @mock.patch('reNgine.celery.app.control.revoke')
    def test_stop_subscan(self, revoke):
        subscan = SubScan.objects.create(type='port_scan', start_scan_date=timezone.now(), status=RUNNING_TASK,
                                         scan_history=self.scan, subdomain=self.sub, celery_ids=['x'])
        self.assertEqual(self.post(f'/subscans/{subscan.id}/stop/').status_code, 200)
        subscan.refresh_from_db()
        self.assertEqual(subscan.status, ABORTED_TASK)
        self.assertEqual(self.post(f'/subscans/{subscan.id}/stop/').status_code, 409)


# ---------------------------------------------------------------- webhook

class WebhookTests(Fixture):
    def setUp(self):
        super().setUp()
        cfg = PentyIntegrationConfig.get()
        cfg.webhook_enabled = True
        cfg.webhook_secret = 's' * 40
        cfg.save()
        self.cfg = cfg

    def test_signature(self):
        sig = webhook.sign('secret', '1700000000', b'{"a":1}')
        import hashlib, hmac
        expected = hmac.new(b'secret', b'1700000000.{"a":1}', hashlib.sha256).hexdigest()
        self.assertEqual(sig, 'sha256=' + expected)

    def test_deliver_success_and_failure(self):
        scan = self.make_scan()
        link = PentyScanLink.objects.create(kind='scan', scan_history=scan, callback_url='https://penty.test/hook',
                                            external_ref='r1')
        session = mock.Mock()
        session.post.return_value = mock.Mock(status_code=204)
        ok, err = webhook.deliver(link, SUCCESS_TASK, self.cfg, session=session)
        self.assertTrue(ok)
        self.assertIsNone(err)
        args, kwargs = session.post.call_args
        body = kwargs['data']
        payload = json.loads(body)
        self.assertEqual(payload['event'], 'scan.finished')
        self.assertEqual(payload['status_name'], 'success')
        self.assertEqual(payload['external_ref'], 'r1')
        self.assertEqual(kwargs['headers']['X-Penty-Signature'],
                         webhook.sign(self.cfg.webhook_secret, kwargs['headers']['X-Penty-Timestamp'], body))
        self.assertFalse(kwargs['allow_redirects'])

        session.post.return_value = mock.Mock(status_code=500)
        with mock.patch('penty_api.webhook.time.sleep'):
            ok, err = webhook.deliver(link, SUCCESS_TASK, self.cfg, session=session)
        self.assertFalse(ok)
        self.assertEqual(err, 'HTTP 500')

    @mock.patch('penty_api.webhook.deliver', return_value=(True, None))
    def test_signal_sends_once_on_terminal_status(self, deliver):
        scan = self.make_scan(RUNNING_TASK)
        PentyScanLink.objects.create(kind='scan', scan_history=scan, callback_url='https://penty.test/hook')
        with self.captureOnCommitCallbacks(execute=True):
            scan.save()  # still running → nothing
        deliver.assert_not_called()

        with self.captureOnCommitCallbacks(execute=True):
            scan.scan_status = SUCCESS_TASK
            scan.save()
        self.assertEqual(deliver.call_count, 1)
        link = PentyScanLink.objects.get(scan_history=scan)
        self.assertEqual(link.last_notified_status, SUCCESS_TASK)
        self.assertTrue(link.last_delivery_ok)

        with self.captureOnCommitCallbacks(execute=True):
            scan.save()  # same status again → no duplicate
        self.assertEqual(deliver.call_count, 1)

    @mock.patch('penty_api.webhook.deliver', return_value=(True, None))
    def test_signal_disabled_or_no_callback(self, deliver):
        scan = self.make_scan(RUNNING_TASK)
        PentyScanLink.objects.create(kind='scan', scan_history=scan, callback_url='')
        with self.captureOnCommitCallbacks(execute=True):
            scan.scan_status = FAILED_TASK
            scan.save()
        deliver.assert_not_called()

        self.cfg.webhook_enabled = False
        self.cfg.save()
        scan2 = self.make_scan(RUNNING_TASK)
        PentyScanLink.objects.create(kind='scan', scan_history=scan2, callback_url='https://penty.test/hook')
        with self.captureOnCommitCallbacks(execute=True):
            scan2.scan_status = SUCCESS_TASK
            scan2.save()
        deliver.assert_not_called()

    @mock.patch('penty_api.webhook.deliver', side_effect=RuntimeError('boom'))
    def test_signal_never_breaks_save(self, _deliver):
        scan = self.make_scan(RUNNING_TASK)
        PentyScanLink.objects.create(kind='scan', scan_history=scan, callback_url='https://penty.test/hook')
        with self.captureOnCommitCallbacks(execute=True):
            scan.scan_status = SUCCESS_TASK
            scan.save()
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, SUCCESS_TASK)

    @mock.patch('penty_api.webhook.deliver', return_value=(True, None))
    def test_subscan_signal(self, deliver):
        scan = self.make_scan()
        sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='www.cyberwhiz.co.uk')
        PentyScanLink.objects.create(kind='subscan', celery_task_id='t-1', callback_url='https://penty.test/hook')
        with self.captureOnCommitCallbacks(execute=True):
            subscan = SubScan.objects.create(type='port_scan', start_scan_date=timezone.now(), status=RUNNING_TASK,
                                             scan_history=scan, subdomain=sub, celery_ids=['t-1'])
        deliver.assert_not_called()
        with self.captureOnCommitCallbacks(execute=True):
            subscan.status = SUCCESS_TASK
            subscan.save()
        self.assertEqual(deliver.call_count, 1)


# ---------------------------------------------------------------- management command

class CommandTests(TestCase):
    def test_create_list_revoke(self):
        from io import StringIO
        from django.core.management import call_command
        User.objects.create_user('svc', password='x')
        out = StringIO()
        call_command('penty_api', 'create-token', '--user', 'svc', '--name', 'dev', stdout=out)
        raw = out.getvalue().strip().splitlines()[-1]
        self.assertTrue(raw.startswith('rgp_'))
        token = PentyApiToken.objects.get()
        self.assertNotIn(raw, token.key_hash)
        call_command('penty_api', 'revoke-token', '--id', str(token.id), stdout=StringIO())
        token.refresh_from_db()
        self.assertIsNotNone(token.revoked_at)

    def test_set_webhook_requires_long_secret(self):
        from io import StringIO
        from django.core.management import call_command
        from django.core.management.base import CommandError
        with mock.patch.dict(os.environ, {'PENTY_SECRET': 'short'}):
            with self.assertRaises(CommandError):
                call_command('penty_api', 'set-webhook', '--enable', '--secret-from-env', 'PENTY_SECRET', stdout=StringIO())
        with mock.patch.dict(os.environ, {'PENTY_SECRET': 'x' * 40}):
            call_command('penty_api', 'set-webhook', '--enable', '--secret-from-env', 'PENTY_SECRET', stdout=StringIO())
        self.assertTrue(PentyIntegrationConfig.get().webhook_enabled)
