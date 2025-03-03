from django.contrib.auth.backends import BaseBackend
from ldap3 import Server, Connection, ALL, SUBTREE
from django.conf import settings
from django.contrib.auth.models import User
from accounts.models import Profile  # Импортируем модель Profile

class LDAPBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        # Создаем объект Server, представляющий LDAP-сервер
        server = Server(settings.LDAP_SERVER, get_info=ALL)

        # Пробуем несколько вариантов Distinguished Name (DN) для пользователя
        dn_variants = [
            f"{username}@norail.local",  # формат userPrincipalName
            f"norail.local\\{username}",  # формат sAMAccountName
            f"CN={username},OU=Users_norail,DC=norail,DC=local"  # оригинальный формат
        ]

        for user_dn in dn_variants:
            try:
                # Пытаемся установить соединение с LDAP-сервером с использованием каждого варианта DN
                conn = Connection(server, user=user_dn, password=password, auto_bind=True)
                
                if conn.bind():
                    print(f"Успешная аутентификация {username} через LDAP с DN: {user_dn}")

                    # Выполняем поиск пользователя в LDAP для получения полного имени (ФИО)
                    conn.search(
                        search_base=settings.LDAP_BASE_DN,
                        search_filter=f"(sAMAccountName={username})",
                        search_scope=SUBTREE,
                        attributes=['displayName']
                    )

                    # Если найдены данные, извлекаем displayName, иначе используем логин как имя
                    if conn.entries:
                        display_name = conn.entries[0].displayName.value
                    else:
                        display_name = username

                    # Получаем или создаем пользователя в Django
                    try:
                        user = User.objects.get(username=username)
                    except User.DoesNotExist:
                        user = User(username=username)
                        user.set_unusable_password()  # Устанавливаем неиспользуемый пароль, т.к. мы не храним пароль в базе данных
                        user.save()

                    # Получаем или создаем профиль пользователя
                    profile, created = Profile.objects.get_or_create(user=user)
                    profile.full_name = display_name  # Сохраняем ФИО в поле full_name профиля
                    profile.save()

                    # Разрываем соединение с LDAP-сервером
                    conn.unbind()
                    return user
            except Exception as e:
                print(f"Не удалось подключиться к LDAP-серверу как {user_dn}: {e}")

        # Если ни один из вариантов DN не сработал, возвращаем None
        return None

    def get_user(self, user_id):
        # Получаем пользователя по его ID
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
