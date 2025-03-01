from django.db import models  # Импортируем модуль models для создания моделей Django
from django.contrib.auth.models import User  # Импортируем встроенную модель User для управления пользователями
from django.utils import timezone  # Импортируем утилиту timezone для работы с датой и временем
from datetime import timedelta  # Импортируем класс timedelta для работы с интервалами времени

# Определяем варианты ролей
ROLE_CHOICES = (
    ('user', 'Пользователь'),
    ('admin', 'Администратор'),
)

# Модель Profile для хранения дополнительных данных о пользователях
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='user')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username