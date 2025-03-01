import logging
from django.contrib.auth.backends import BaseBackend
from ldap3 import Server, Connection, ALL, SUBTREE
from django.conf import settings
from django.contrib.auth.models import User
from accounts.models import Profile  # Импорт модели Profile из приложения accounts

# Настраиваем логирование
logger = logging.getLogger(__name__)

class LDAPBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        """
        Аутентификация пользователя через LDAP-сервер.
        
        Пробует несколько вариантов DN (Distinguished Name) для заданного username.
        Если аутентификация успешна, возвращает объект User (создавая его, если необходимо).
        """
        # Создаем объект Server для LDAP-сервера
        server = Server(settings.LDAP_SERVER, get_info=ALL)

        # Определяем варианты DN для пользователя
        dn_variants = [
            f"{username}@norail.local",           # Формат userPrincipalName
            f"norail.local\\{username}",           # Формат sAMAccountName
            f"CN={username},OU=Users_norail,DC=norail,DC=local"  # Оригинальный формат
        ]

        for user_dn in dn_variants:
            try:
                # Устанавливаем соединение с LDAP-сервером, используя данный вариант DN
                conn = Connection(server, user=user_dn, password=password, auto_bind=True)
                
                # Если соединение успешно установлено
                if conn.bind():
                    logger.info(f"Успешная аутентификация {username} через LDAP с DN: {user_dn}")

                    # Выполняем поиск пользователя в LDAP для получения полного имени (displayName)
                    conn.search(
                        search_base=settings.LDAP_BASE_DN,
                        search_filter=f"(sAMAccountName={username})",
                        search_scope=SUBTREE,
                        attributes=['displayName']
                    )

                    # Если найдены данные, извлекаем displayName, иначе используем username
                    if conn.entries:
                        display_name = conn.entries[0].displayName.value
                    else:
                        display_name = username

                    # Получаем или создаем пользователя в Django
                    try:
                        user = User.objects.get(username=username)
                    except User.DoesNotExist:
                        user = User(username=username)
                        user.set_unusable_password()  # Пароль не используется, так как аутентификация через LDAP
                        user.save()

                    # Получаем или создаем профиль пользователя и сохраняем displayName
                    profile, created = Profile.objects.get_or_create(user=user)
                    profile.full_name = display_name
                    profile.save()

                    # Разрываем соединение с LDAP-сервером
                    conn.unbind()
                    return user
            except Exception as e:
                logger.error(f"Не удалось подключиться к LDAP-серверу с DN {user_dn}: {e}")
                # Можно добавить продолжение цикла для следующих вариантов DN

        # Если ни один вариант DN не сработал, возвращаем None
        return None

    def get_user(self, user_id):
        """
        Получает объект User по его ID.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None