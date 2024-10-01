from werkzeug.security import generate_password_hash

# Задаем пароль, который нужно захешировать
password = "visterainer2134"

# Генерируем хеш пароля
hashed_password = generate_password_hash(password, method="pbkdf2")

print(hashed_password)
