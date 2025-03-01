from django.urls import path  # Импортируем функцию path для определения маршрутов (URL-ов) приложения
from . import views  # Импортируем views из текущего приложения, где находятся все функции обработки запросов
from django.shortcuts import redirect

# Определение списка URL-путей для приложения
urlpatterns = [
    path('login/', views.user_login, name='login'),  # Путь для входа пользователя в систему
    path('logout/', views.user_logout, name='logout'),  # Путь для выхода пользователя из системы
    path('register/', views.register, name='register'),  # Путь для регистрации нового пользователя
#    path('map/', views.map_view, name='map_view'),  #пути для отображения основгоного приложения
#    path('', lambda request: redirect('map_view')),
]
