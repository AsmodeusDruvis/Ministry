
from django.contrib import admin
from django.urls import path , include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

# Gates of the capital

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/v1/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    path('auth/' , include('AuthAndRegister.urls')),
    
]

