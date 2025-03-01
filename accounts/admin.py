# Файл: accounts/admin.py

from django.contrib import admin
from .models import Profile

# Класс админки для профиля пользователя
class ProfileAdmin(admin.ModelAdmin):
    # Отображаемые поля в списке профилей
    # Если в модели добавлены поля 'role' и 'created_at', их можно включить для более подробного отображения.
    list_display = ('user', 'full_name', 'role', 'is_active', 'created_at')
    
    # Фильтры для боковой панели в админке
    list_filter = ('is_active', 'role')
    
    # Поля, по которым осуществляется поиск
    search_fields = ('user__username', 'user__email', 'full_name')
    
    # Определяем действия для массового обновления статуса пользователей
    actions = ['activate_users', 'deactivate_users']

    # Метод для активации пользователей
    def activate_users(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, "Selected users were successfully activated.")

    # Метод для деактивации пользователей
    def deactivate_users(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, "Selected users were successfully deactivated.")

    # Краткие описания для действий в админке
    activate_users.short_description = "Activate selected users"
    deactivate_users.short_description = "Deactivate selected users"

# Регистрация модели Profile с классом админки
admin.site.register(Profile, ProfileAdmin)
