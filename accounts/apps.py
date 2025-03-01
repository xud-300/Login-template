from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'
    verbose_name = "Управление аккаунтами"

    def ready(self):
        # Здесь можно импортировать модули с сигналами или выполнить другую инициализацию
        import accounts.signals  # если у вас есть файл signals.py