def get_client_ip(request):
    """
    Функция для получения IP-адреса клиента из HTTP-запроса.
    
    :param request: HTTP-запрос, содержащий информацию о клиенте.
    :return: Строка с IP-адресом клиента.
    """
    # Пытаемся получить IP-адрес из заголовка 'HTTP_X_FORWARDED_FOR'
    ip = request.META.get('HTTP_X_FORWARDED_FOR')
    
    if not ip:
        # Если 'HTTP_X_FORWARDED_FOR' отсутствует, используем 'REMOTE_ADDR'
        ip = request.META.get('REMOTE_ADDR')
    else:
        # Если 'HTTP_X_FORWARDED_FOR' содержит несколько IP-адресов, берем первый (это IP клиента)
        ip = ip.split(',')[0].strip()
    
    return ip