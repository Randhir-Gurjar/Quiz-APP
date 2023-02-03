# # Password Hashing:
# import bcrypt
# password = 'RVKvamsi23'.encode('utf-8')

# hashed = bcrypt.hashpw(password, bcrypt.gensalt())
# hashed



# # Password Verification:

# user_password=b'RVKvamsi23'
# hashed_password = b'$2b$12$YP.zABA9JYXN3lzUUPjKa.zOGU7dd2c5lro6JHhpRLTjX8m.J7.YO'

# hash2 =  bcrypt.hashpw(user_password,hashed_password)

# if bcrypt.checkpw(user_password,hashed_password):
#     print(hashed_password==hash2)
#     print('Verified')
# else:
#     print('Not Verified')

import password_to_hash as ps
import password_ver as pv

password='asfg'
hash=ps.text_hash(password)
# print (hash)

