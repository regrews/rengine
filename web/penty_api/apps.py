from django.apps import AppConfig


class PentyApiConfig(AppConfig):
    name = 'penty_api'
    verbose_name = 'Penty Integration API'
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Register signal handlers (scan / subscan status → webhook).
        from penty_api import signals  # noqa: F401
