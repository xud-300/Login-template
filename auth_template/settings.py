from pathlib import Path
import os
import environ

# Определение базовой директории проекта
BASE_DIR = Path(__file__).resolve().parent.parent

# Инициализация django-environ
env = environ.Env(
    DEBUG=(bool, False)
)
# Загружаем переменные из файла .env
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# Основные настройки
DEBUG = env.bool('DEBUG')
SECRET_KEY = env('SECRET_KEY')

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1'])

# Настройки безопасности
CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[])
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_COOKIE_HTTPONLY = False

# Настройки URL для входа и выхода пользователя
# LOGIN_URL = 'login'
# LOGOUT_URL = 'logout'
# LOGIN_REDIRECT_URL = '/'

# Установленные приложения в проекте
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'captcha',
    'main_app',
]

# Промежуточное ПО (middleware)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Корневой URL-конфиг
ROOT_URLCONF = 'auth_template.urls'

# Настройки шаблонов
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# WSGI-приложение
WSGI_APPLICATION = 'auth_template.wsgi.application'

# Настройки базы данных
DATABASES = {
    'default': env.db(
        # Формируем строку подключения к базе данных вручную:
        'DATABASE_URL',
        default=f"postgres://{env('DATABASE_USER')}:{env('DATABASE_PASSWORD')}@{env('DATABASE_HOST')}:{env('DATABASE_PORT')}/{env('DATABASE_NAME')}"
    )
}

# Настройки валидаторов паролей (пустой список)
AUTH_PASSWORD_VALIDATORS = []

# Локализация
LANGUAGE_CODE = 'ru'
TIME_ZONE = env('TIME_ZONE', default='Asia/Bangkok')
USE_I18N = True
USE_TZ = True

# Статические файлы
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = env('STATIC_ROOT')

# URL для редиректа после входа и выхода
LOGIN_REDIRECT_URL = 'main_page'
LOGOUT_REDIRECT_URL = '/'

# Настройки по умолчанию для первичных ключей
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Настройки аутентификации через LDAP
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'auth_template.ldap_auth_backend.LDAPBackend',

)

# Параметры подключения к серверу LDAP
LDAP_SERVER = env('LDAP_SERVER')
LDAP_BASE_DN = env('LDAP_BASE_DN')
LDAP_USER_DN = env('LDAP_USER_DN')
LDAP_BIND_USER_DN = env('LDAP_BIND_USER_DN')
LDAP_BIND_USER_PASSWORD = env('LDAP_BIND_USER_PASSWORD')

# Настройки reCAPTCHA
RECAPTCHA_PUBLIC_KEY = env('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = env('RECAPTCHA_PRIVATE_KEY')

# Настройки кэширования
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}
