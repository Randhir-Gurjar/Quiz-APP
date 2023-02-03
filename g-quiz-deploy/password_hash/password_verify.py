from deta import Deta
import bcrypt
from dotenv import get_key
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
User_logged = None
lsc=None
def password_verify(user_name,user_password):
    global User_logged
    global lsc
    # User_logged = None
    project_key =get_key(key_to_get="Project_Key",dotenv_path=".env")
    deta = Deta(project_key=project_key)
    user_database = deta.Base('login_data')
    # admin_database=deta.Base('admin_data')

    try:
        user_password=str(user_password)
        user_password=user_password.encode('utf-8')
        try:
            query = user_database.fetch(query={'key':user_name}).items[0]
            hashed_password = query['Password'].encode('utf-8')
            # global lsc
            lsc=user_database.fetch(query={'key':user_name}).items[0]
            lsc=lsc['score']
        # hash2 =  bcrypt.hashpw(user_password,hashed_password)

            if bcrypt.checkpw(user_password,hashed_password):
                # print(hashed_password==hash2)
                # print('Verified')
                User_logged = query
                return 'User Verified'
            else:
                print('Not Verified')
                return 'Incorrect Password'


        except IndexError as ie:
            if IndexError:
                print(ie)
                return 'No Data Found, Create Account'

            # else:

    except Exception as e:
        print(e)
        print("not found")

def password_verify1(admin_name,admin_password):

    project_key =get_key(key_to_get="Project_Key",dotenv_path=".env")
    deta = Deta(project_key=project_key)
    admin_database = deta.Base('admin_data')
    global User_logged
    try:
        admin_password=str(admin_password)
        admin_password=admin_password.encode('utf-8')
        try:
            query = admin_database.fetch(query={'key':admin_name}).items[0]
            hashed_password = query['Password'].encode('utf-8')
            if bcrypt.checkpw(admin_password,hashed_password):
                User_logged = query
                return 'User Verified'
            else:
                print('Not Verified')
                return 'Incorrect Password'
        except IndexError as ie:
            if IndexError:
                print(ie)
                return 'No Data Found, Invalid credentials'

    except Exception as e:
        print(e)
        print("not found")