from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from captcha.fields import ReCaptchaField  # Импорт капчи
from .models import Profile


# Форма для регистрации новых пользователей
class UserRegistrationForm(UserCreationForm):
    full_name = forms.CharField(max_length=255, label="ФИО")  # Поле для ввода полного имени пользователя

    # Поля для ввода и подтверждения пароля
    password1 = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput,
        help_text="Введите пароль."  # Подсказка для ввода пароля
    )
    password2 = forms.CharField(
        label="Подтверждение пароля",
        widget=forms.PasswordInput,
        help_text="Введите тот же пароль, что и выше, для проверки."  # Подсказка для подтверждения пароля
    )

    def __init__(self, *args, **kwargs):
        super(UserRegistrationForm, self).__init__(*args, **kwargs)
        # Добавляем капчу в форму регистрации всегда
        print("Adding captcha to registration form")  # Выводим сообщение о добавлении капчи
        self.fields['captcha'] = ReCaptchaField()  # Добавляем поле капчи в форму


    class Meta: 
        model = User  # Указываем, что форма связана с моделью User
        fields = ['username', 'password1', 'password2', 'full_name']  # Определяем, какие поля модели будут отображаться в форме
        labels = {
            'username': 'Имя пользователя',  # Метка для поля "username"
            'password1': 'Пароль',  # Метка для поля "password1"
            'password2': 'Подтверждение пароля',  # Метка для поля "password2"
        }
        help_texts = {
            'username': 'Обязательно. Не более 150 символов. Только буквы, цифры и @/./+/-/_.',  # Подсказка для поля "username"
        }
    


    def clean(self):
        """Переопределение метода clean для дополнительной проверки паролей."""
        cleaned_data = super().clean()  # Вызываем метод clean() базового класса для выполнения стандартных проверок
        password1 = cleaned_data.get("password1")  # Получаем значение первого пароля
        password2 = cleaned_data.get("password2")  # Получаем значение второго пароля

        if password1 and password2 and password1 != password2:  # Если пароли не совпадают
            self.add_error('password2', "Пароли не совпадают.")  # Добавляем ошибку в поле "password2"

        return cleaned_data  # Возвращаем очищенные данные

    def save(self, commit=True):
        """Переопределение метода save для создания профиля пользователя после сохранения."""
        user = super().save(commit=False)  # Сохраняем пользователя, но не фиксируем изменения в базе данных
        if commit:  # Если нужно сразу сохранить данные в базе
            user.save()  # Сохраняем пользователя
            # Создаем профиль пользователя и связываем его с текущим пользователем
            profile = Profile(user=user, full_name=self.cleaned_data['full_name'], role=self.cleaned_data['role'])
            profile.save()  # Сохраняем профиль
        return user  # Возвращаем объект пользователя


# Кастомизированная форма аутентификации с возможностью добавления капчи
class CustomAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        self.failed_attempts = kwargs.pop('failed_attempts', 0)  # Извлекаем количество неудачных попыток из переданных аргументов
        self.reset_captcha = kwargs.pop('reset_captcha', False)  # Извлекаем флаг сброса капчи из переданных аргументов
        super().__init__(*args, **kwargs)  # Вызываем конструктор базового класса
        
        username = self.data.get('username', None)  # Получаем имя пользователя из данных формы
        print(f"Failed attempts for {username}: {self.failed_attempts}")  # Выводим в консоль количество неудачных попыток для пользователя
        
        # Добавляем капчу, если количество попыток больше или равно 3 и капча не была сброшена
        if self.failed_attempts >= 3 and not self.reset_captcha:
            print("Adding captcha to form")  # Выводим сообщение о добавлении капчи
            self.fields['captcha'] = ReCaptchaField()  # Добавляем поле капчи в форму
        else:
            print("Captcha not added to form")  # Выводим сообщение, если капча не была добавлена
