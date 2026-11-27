"""Manage Penty API tokens and webhook settings.

  python3 manage.py penty_api create-token --user penty-service --name penty-dev
  python3 manage.py penty_api list-tokens
  python3 manage.py penty_api revoke-token --id 3
  python3 manage.py penty_api set-webhook --enable --secret-from-env PENTY_WEBHOOK_SECRET --allowed-prefix https://penty.example/
  python3 manage.py penty_api set-webhook --disable
  python3 manage.py penty_api show-config
"""
import os

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from penty_api.models import PentyApiToken, PentyIntegrationConfig


class Command(BaseCommand):
    help = 'Manage Penty Integration API tokens and webhook configuration.'

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest='action', required=True)

        create = sub.add_parser('create-token')
        create.add_argument('--user', required=True)
        create.add_argument('--name', required=True)

        sub.add_parser('list-tokens')

        revoke = sub.add_parser('revoke-token')
        revoke.add_argument('--id', type=int, required=True)

        hook = sub.add_parser('set-webhook')
        group = hook.add_mutually_exclusive_group(required=True)
        group.add_argument('--enable', action='store_true')
        group.add_argument('--disable', action='store_true')
        hook.add_argument('--secret-from-env', help='Read the HMAC secret from this env variable')
        hook.add_argument('--allowed-prefix', help='Only allow callback URLs starting with this prefix')

        sub.add_parser('show-config')

    def handle(self, *args, **opts):
        action = opts['action']
        if action == 'create-token':
            user = User.objects.filter(username=opts['user'], is_active=True).first()
            if not user:
                raise CommandError(f'active user "{opts["user"]}" not found')
            token, raw = PentyApiToken.issue(user, opts['name'])
            self.stdout.write(f'Token id {token.id} created for {user.username}. Store it now, it is not shown again:')
            self.stdout.write(raw)
        elif action == 'list-tokens':
            for t in PentyApiToken.objects.select_related('user'):
                state = 'revoked' if t.revoked_at else 'active'
                self.stdout.write(f'{t.id}\t{t.key_prefix}…\t{t.user.username}\t{t.name}\t{state}\tlast_used={t.last_used_at}')
        elif action == 'revoke-token':
            updated = PentyApiToken.objects.filter(pk=opts['id'], revoked_at__isnull=True).update(revoked_at=timezone.now())
            if not updated:
                raise CommandError('token not found or already revoked')
            self.stdout.write(f'Token {opts["id"]} revoked.')
        elif action == 'set-webhook':
            cfg = PentyIntegrationConfig.get()
            if opts['enable']:
                env_name = opts.get('secret_from_env')
                if env_name:
                    secret = os.environ.get(env_name, '')
                    if len(secret) < 32:
                        raise CommandError(f'env {env_name} must hold a secret of at least 32 chars')
                    cfg.webhook_secret = secret
                if not cfg.webhook_secret:
                    raise CommandError('no webhook secret configured; pass --secret-from-env')
                cfg.webhook_enabled = True
            else:
                cfg.webhook_enabled = False
            if opts.get('allowed_prefix') is not None:
                cfg.allowed_callback_prefix = opts['allowed_prefix']
            cfg.save()
            self.stdout.write(f'webhook_enabled={cfg.webhook_enabled} allowed_prefix="{cfg.allowed_callback_prefix}"')
        elif action == 'show-config':
            cfg = PentyIntegrationConfig.get()
            self.stdout.write(
                f'webhook_enabled={cfg.webhook_enabled} secret_set={bool(cfg.webhook_secret)} '
                f'allowed_prefix="{cfg.allowed_callback_prefix}"')
