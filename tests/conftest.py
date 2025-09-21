# File: tests/conftest.py

import pytest
from django.conf import settings
from django.test.utils import get_runner


def pytest_configure():
    """Configure Django for tests."""
    settings.configure(
        DEBUG=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'rest_framework',
            'auth_integration',
            'users',
        ],
        SECRET_KEY='test-secret-key',
        USE_TZ=True,
        ROOT_URLCONF='pefoma_backend.urls',
        MIDDLEWARE=[
            'auth_integration.middleware.SupabaseJWTMiddleware',
        ],
        REST_FRAMEWORK={
            'DEFAULT_AUTHENTICATION_CLASSES': [
                'auth_integration.authentication.SupabaseAuthentication',
            ],
        },
        SUPABASE_URL='https://test.supabase.co',
        SUPABASE_ANON_KEY='test-anon-key',
        SUPABASE_SERVICE_ROLE_KEY='test-service-key',
        SUPABASE_JWT_SECRET='test-jwt-secret',
    )
    
    import django
    django.setup()