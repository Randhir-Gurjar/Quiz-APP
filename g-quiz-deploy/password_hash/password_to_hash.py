import bcrypt
def text_hash(password):
    password = str(password)
    password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password

