// Функция, вызываемая при успешном прохождении капчи
function onCaptchaSuccess() {
    console.log("Captcha passed successfully");
    // Активируем кнопки после успешного прохождения капчи
    document.getElementById('login-button').disabled = false;
    document.getElementById('register-button').disabled = false;
}

// Функция, вызываемая, когда капча истекает
function onCaptchaExpired() {
    console.log("Captcha expired");
    // Деактивируем кнопки, если срок действия капчи истек
    document.getElementById('login-button').disabled = true;
    document.getElementById('register-button').disabled = true;
}

// Функция сброса и рендеринга капчи в заданном контейнере
function resetAndRenderCaptcha(captchaContainerId) {
    const captchaContainer = document.getElementById(captchaContainerId);

    if (captchaContainer) {
        // Очищаем контейнер перед рендерингом новой капчи
        captchaContainer.innerHTML = '';

        // Получаем sitekey непосредственно из атрибута data-sitekey или задаем его напрямую
        const siteKey = captchaContainer.dataset.sitekey || '6Le9rCQqAAAAALGIS2aWUBCVhlS8EojJ4_q0BeNS';

        // Создаем новый элемент для капчи
        const newCaptcha = document.createElement('div');
        newCaptcha.className = 'g-recaptcha';
        // Устанавливаем атрибуты для капчи
        newCaptcha.setAttribute('data-sitekey', siteKey);
        newCaptcha.setAttribute('data-callback', 'onCaptchaSuccess');
        newCaptcha.setAttribute('data-expired-callback', 'onCaptchaExpired');

        captchaContainer.appendChild(newCaptcha);

        // Рендерим капчу
        if (typeof grecaptcha !== 'undefined') {
            grecaptcha.render(newCaptcha, {
                'sitekey': siteKey,
                'callback': onCaptchaSuccess,
                'expired-callback': onCaptchaExpired
            });
            console.log("reCAPTCHA сброшена и отрендерена заново для формы " + captchaContainerId);
        } else {
            console.error("grecaptcha не загружена.");
        }
    } else {
        console.error("Элемент с id " + captchaContainerId + " не найден.");
    }
}

// Анимация фона после загрузки страницы
document.addEventListener("DOMContentLoaded", function() {
    let backgrounds = document.querySelectorAll(".background");
    let currentIndex = 0;
    const transitionTime = 6000; // Время между сменой фонов
    const fadeTime = 3000; // Время затухания

    setInterval(() => {
        let previousIndex = currentIndex;
        currentIndex = (currentIndex + 1) % backgrounds.length;

        // Устанавливаем плавное исчезновение для предыдущего фона
        backgrounds[previousIndex].style.transition = `opacity ${fadeTime / 200}s ease-in-out`;
        backgrounds[previousIndex].style.opacity = 0;

        // Устанавливаем плавное появление для текущего фона
        backgrounds[currentIndex].style.transition = `opacity ${fadeTime / 700}s ease-in-out`;
        backgrounds[currentIndex].style.opacity = 1;
    }, transitionTime);
});

// Использование jQuery для обработки событий после загрузки документа
$(document).ready(function() {
    // Проверка аутентификации: если пользователь уже залогинен, перенаправляем его
    if ("{{ user.is_authenticated }}" === "True") {
        window.location.href = "{% url 'map_view' %}";
        return; // Прерываем выполнение скрипта, если пользователь аутентифицирован
    }

    // Получаем количество неудачных попыток входа (из контекста Django)
    let failedAttempts = parseInt("{{ failed_attempts|default:0 }}", 10);
    let captchaShown = failedAttempts >= 3;

    // Если количество неудачных попыток >= 3, показываем капчу сразу для формы аутентификации
    if (captchaShown) {
        $("#captcha-container").show();
        document.getElementById('login-button').disabled = true; // Деактивируем кнопку входа
        resetAndRenderCaptcha('captcha-container'); // Рендерим капчу
    }

    // Обработчик закрытия модального окна регистрации
    $('#registerModal').on('hidden.bs.modal', function () {
        // Убираем затемнение и удаляем фоновые элементы модального окна
        $('body').removeClass('modal-open');
        $('.modal-backdrop').remove();
        // Очищаем форму регистрации
        $('#registrationForm').trigger("reset");
        // Убираем сообщения об ошибках
        $(".invalid-feedback").remove();
        $(".form-control").removeClass("is-invalid");
    });

    // Обработчик отправки формы регистрации
    $("#registrationForm").submit(function(event) {
        event.preventDefault();

        $(".invalid-feedback").remove();
        $(".form-control").removeClass("is-invalid");

        $.ajax({
            url: "/register/",
            type: "POST",
            data: $(this).serialize(),
            success: function(response) {
                if (response.success) {
                    if (typeof $.fn.modal === 'function') {
                        $("#registerModal").modal("hide");
                    } else {
                        console.error("Bootstrap Modal не поддерживается.");
                    }
                    $('body').removeClass('modal-open');
                    $('.modal-backdrop').remove();

                    Swal.fire({
                        icon: 'success',
                        title: 'Успех!',
                        text: response.message,
                        position: 'top',
                        heightAuto: false,
                        showConfirmButton: true,
                        confirmButtonText: 'OK',
                        customClass: {
                            popup: 'swal-custom-mobile'
                        }
                    });
                } else {
                    if (response.errors) {
                        for (let field in response.errors) {
                            let $field = $(`[name="${field}"]`);
                            $field.addClass("is-invalid");
                            if ($field.next(".invalid-feedback").length === 0) {
                                $field.after(`<div class="invalid-feedback">${response.errors[field].join('<br>')}</div>`);
                            }
                        }
                    }
                    // Сбрасываем капчу при наличии ошибок
                    resetAndRenderCaptcha('register-captcha-container');
                    document.getElementById('register-button').disabled = true;
                }
            },
            error: function(xhr) {
                if (xhr.responseJSON && xhr.responseJSON.errors) {
                    let errors = xhr.responseJSON.errors;
                    for (let field in errors) {
                        let $field = $(`[name="${field}"]`);
                        $field.addClass("is-invalid");
                        if ($field.next(".invalid-feedback").length === 0) {
                            $field.after(`<div class="invalid-feedback">${errors[field].join('<br>')}</div>`);
                        }
                    }
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Ошибка!',
                        text: 'Произошла ошибка при регистрации. Попробуйте еще раз.',
                        confirmButtonText: 'OK'
                    });
                }
                // Сбрасываем капчу при ошибке
                resetAndRenderCaptcha('register-captcha-container');
                document.getElementById('register-button').disabled = true;
            }
        });
    });

    // Обработчик отправки формы входа
    $("#loginForm").submit(function(event) {
        event.preventDefault();

        $("#spinner").show();
        document.getElementById('login-button').disabled = true;

        $.ajax({
            url: "{% url 'login' %}",
            type: "POST",
            data: $(this).serialize(),
            success: function(response) {
                $("#spinner").hide();
                if (response.success) {
                    window.location.href = response.redirect_url;
                } else {
                    $("#spinner").hide();
                    if (response.reset_captcha || failedAttempts >= 3) {
                        $("#captcha-container").show();
                        document.getElementById('login-button').disabled = true;
                        resetAndRenderCaptcha('captcha-container');
                        captchaShown = true;
                    }
                    failedAttempts += 1;
                    console.log("Ошибка входа:", response);
                    let errorMessage = 'Неверный логин или пароль. Попробуйте еще раз.';
                    if (response.errors && response.errors.captcha) {
                        errorMessage = 'Неверная капча. Попробуйте еще раз.';
                    }
                    Swal.fire({
                        icon: 'error',
                        title: 'Ошибка!',
                        text: errorMessage,
                        confirmButtonText: 'OK',
                        customClass: {
                            popup: 'swal-custom-mobile'
                        }
                    });
                    if (!captchaShown) {
                        document.getElementById('login-button').disabled = false;
                    } else {
                        resetAndRenderCaptcha('captcha-container');
                    }
                }
            },
            error: function(xhr) {
                $("#spinner").hide();
                console.error("Произошла ошибка во время входа:", xhr);
                Swal.fire({
                    icon: 'error',
                    title: 'Ошибка!',
                    text: 'Произошла ошибка. Попробуйте еще раз.',
                    confirmButtonText: 'OK',
                    customClass: {
                        popup: 'swal-custom-mobile'
                    }
                });
                document.getElementById('login-button').disabled = false;
                resetAndRenderCaptcha('captcha-container');
            }
        });
    });

    // Кастомные стили для SweetAlert на мобильных устройствах
    var style = document.createElement('style');
    style.innerHTML = `
        @media (max-width: 980px) {
            .swal-custom-mobile {
                width: 70% !important;
                font-size: 1.6em !important;
            }
            .swal2-popup {
                width: 80% !important;
            }
            .swal2-title {
                font-size: 1.8em !important;
            }
            .swal2-content {
                font-size: 1.4em !important;
            }
            .swal2-confirm {
                font-size: 1.3em !important;
            }
        }
    `;
    document.head.appendChild(style);
});
