# File: pefoma_backend/urls.py

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.views import View


class HealthCheckView(View):
    """Simple health check endpoint."""
    
    def get(self, request):
        return JsonResponse({
            'status': 'healthy',
            'service': 'pefoma-backend',
            'version': '1.0.0'
        })

from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="My API",
      default_version='v1',
      description="API documentation for my Django project",
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # Health check
    path('health/', HealthCheckView.as_view(), name='health_check'),
    
    # API endpoints
    path('auth/', include('auth_integration.urls')),
    path('users/', include('users.urls')),
    path('api/', include('api.urls')),

    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]