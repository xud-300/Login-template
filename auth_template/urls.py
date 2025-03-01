from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('main_app/', include('main_app.urls')),  # подключаем маршруты main_app
    path('', lambda request: redirect('login')),  # редирект с корня на страницу входа (если нужно)
]
