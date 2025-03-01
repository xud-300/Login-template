import logging
from django.db.models.signals import post_save  # Импортируем сигнал post_save
from django.contrib.auth.models import User  # Импортируем встроенную модель User
from django.dispatch import receiver  # Импортируем декоратор receiver
from .models import Profile  # Импортируем модель Profile

# Настраиваем логирование
logger = logging.getLogger(__name__)

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    """
    Обработчик сигнала, который вызывается после создания нового пользователя.
    Если пользователь был создан, создается профиль для него.
    """
    if created:
        Profile.objects.create(user=instance)
        logger.info(f"Profile created for user: {instance.username}")

@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    """
    Обработчик сигнала, который вызывается после сохранения пользователя.
    Пытается сохранить связанный профиль. Если профиль не существует, создает его.
    """
    try:
        instance.profile.save()
    except Profile.DoesNotExist:
        Profile.objects.create(user=instance)
        logger.info(f"Profile created on save for user: {instance.username}")