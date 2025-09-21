# File: auth_integration/apps.py

from django.apps import AppConfig


class AuthIntegrationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth_integration'
    verbose_name = 'Authentication Integration'
    
    def ready(self):
        """Initialize app when Django starts."""
        # Import any signals or background tasks here
        pass