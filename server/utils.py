import bcrypt
import random
import string

# Mã hóa mật khẩu
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Xác thực mật khẩu
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Tạo URL duy nhất cho ghi chú
def generate_note_url():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))