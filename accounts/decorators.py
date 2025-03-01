from functools import wraps  # Для сохранения информации о декорируемой функции
from django.http import HttpResponseForbidden  # Для возврата ошибки доступа
from .models import Profile  # Импортируем модель Profile для работы с профилями пользователей

def role_required(allowed_roles):
    """
    Декоратор, который проверяет, имеет ли пользователь одну из разрешенных ролей.

    :param allowed_roles: Список разрешенных ролей.
    :return: Функция-декоратор, которая проверяет роль пользователя.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Проверяем, авторизован ли пользователь
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Вы не авторизованы.")
            
            try:
                # Получаем профиль текущего пользователя
                user_profile = Profile.objects.get(user=request.user)
            except Profile.DoesNotExist:
                return HttpResponseForbidden("Профиль пользователя не найден.")
            
            # Проверяем, имеет ли пользователь одну из разрешенных ролей
            if user_profile.role not in allowed_roles:
                return HttpResponseForbidden("Вы не имеете прав для выполнения этой операции.")
            
            # Если проверка пройдена, вызываем оригинальную view-функцию
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    return decorator

# Декоратор для ограничения доступа только для редакторов и администраторов
editor_required = role_required(['editor', 'admin'])

# Декоратор для ограничения доступа только для администраторов
admin_required = role_required(['admin'])