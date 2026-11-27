from datetime import timedelta

from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rolepermissions.checkers import has_permission

from penty_api.models import PentyApiToken, hash_token

LAST_USED_RESOLUTION = timedelta(minutes=1)


class PentyTokenAuthentication(BaseAuthentication):
    """`Authorization: Bearer <token>` (or `Token <token>`).

    No session, no CSRF. Returns 401 (not 403) when the header is missing or invalid.
    """
    keywords = (b'bearer', b'token')

    def authenticate(self, request):
        parts = get_authorization_header(request).split()
        if not parts or parts[0].lower() not in self.keywords:
            return None
        if len(parts) != 2:
            raise AuthenticationFailed('Invalid Authorization header.')
        try:
            raw = parts[1].decode('utf-8')
        except UnicodeError:
            raise AuthenticationFailed('Invalid token.')

        token = (
            PentyApiToken.objects
            .select_related('user')
            .filter(key_hash=hash_token(raw), revoked_at__isnull=True)
            .first()
        )
        if not token or not token.user.is_active:
            raise AuthenticationFailed('Invalid or revoked token.')

        now = timezone.now()
        if not token.last_used_at or now - token.last_used_at > LAST_USED_RESOLUTION:
            PentyApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
        return (token.user, token)

    def authenticate_header(self, request):
        return 'Bearer realm="penty-api"'


class HasRenginePermission(BasePermission):
    """Checks reNgine's role permission named in `view.permission_required` (if any)."""
    message = 'This user does not have enough permissions.'

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        required = getattr(view, 'permission_required', None)
        if isinstance(required, dict):
            required = required.get(request.method)
        if not required:
            return True
        return has_permission(request.user, required)
