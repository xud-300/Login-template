from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required  # Только авторизованные пользователи могут видеть эту страницу
def main_page(request):
    """
    Представление главной страницы основного приложения.
    """
    return render(request, 'main_app/main.html')