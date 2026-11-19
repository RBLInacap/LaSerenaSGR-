from django.apps import AppConfig


class SgrAppConfig(AppConfig):
    name = 'sgr_app'

    def ready(self):
        from sgr_app import signals  # noqa: F401  (registra los receptores)
        from sgr_app import openapi  # noqa: F401  (registra el esquema JWT de Swagger)
