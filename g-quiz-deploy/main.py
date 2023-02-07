from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_login import login_user, login_required, LoginManager, logout_user, UserMixin
import password_hash.password_verify as pv
import password_hash.password_to_hash as ps
from PIL import Image, ImageDraw, ImageFont
from dotenv import get_key, load_dotenv
from datetime import timedelta
from deta import Deta
import pandas as pd
import numpy as np
import random
import ssl
import os

ssl._create_default_https_context = ssl._create_unverified_context
load_dotenv()
app = Flask(__name__, template_folder="templates")
app.jinja_env.filters['zip'] = zip
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
flag = False


@app.before_request
def set_session():
    if "user" in session:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=20)
        session.modified = True
        g.user = session["user"]
    else:
        g.user = None


@app.route('/')
def home():
    if g.user:
        return redirect("/error")
    else:
        return render_template('index.html')


@app.route('/logout')
def logout():
    if g.user:
        session.clear()
        return redirect('/')
    else:
        return redirect("/login")


@app.route('/error')
def errorPage():
    session.clear()
    return render_template('error.html')


@app.route('/login', methods=['POST', 'GET'])
def ur():
    global user_mail
    global lscore
    global userLogged
    userLogged = None
    lscore = None
    user_mail = ""

    project_key = get_key(key_to_get="Project_Key", dotenv_path=".env")
    # Logging into Deta:
    deta = Deta(project_key=project_key)
    database = deta.Base("login_data")

    if request.method == "POST":
        submit_btn = list(request.form)[::-1]

# ************************************************************************* Sign IN ******************************************************************************************
        if submit_btn[0] == 'sign-in':
            user_mail = request.form["email"]
            user_pas = request.form['password']
            verification_msg = pv.password_verify(
                user_name=user_mail, user_password=user_pas)
            if verification_msg == 'User Verified':
                userLogged = pv.User_logged
               #  ********************************************************* login_user ****************************************************************************************
                session['user'] = user_mail
                lscore = pv.lsc
                return redirect('/quiz-start')
            elif verification_msg == 'Incorrect Password':
                flash(message=verification_msg, category='Error')
            elif verification_msg == 'No Data Found, Create Account':
                flash(message=verification_msg, category='Error')

# *************************************************************************** Sign Up ****************************************************************************************
        elif submit_btn[0] == 'sign-up':

            user_name = request.form["name"]
            user_mail = request.form["email"]
            user_pas1 = request.form['password1']
            user_pas2 = request.form['password2']

            if user_pas1 == user_pas2:
                hash = ps.text_hash(user_pas2)
                hash = hash.decode()
                try:
                    database.insert({'key': user_mail, 'Name': user_name, 'Password': hash,
                                    'score': [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1]})
                    msg = 'Registration Successfull'
                    flash(message=msg, category='Success')
                    return redirect('/login')

                except Exception as e:
                    print(e)
                    if 'Conflict' in str(e):
                        msg = 'User Already Exists, Sign In'
                        flash(message=msg, category='Error')
                        return redirect('/login')
            else:
                msg = "Password Doesn't Match"
                flash(message=msg, category='Error')

    return render_template('login.html')


@app.route('/adminlogin', methods=['POST', 'GET'])
def al():
    global user_mail

    if request.method == "POST":
        submit_btn = list(request.form)

# ************************************************************************************** Admin sign_in ********************************************************************
        if submit_btn[2] == 'sign-in':
            admin_mail = request.form["email"]
            admin_pas = request.form['password']

            verification_msg = pv.password_verify1(
                admin_name=admin_mail, admin_password=admin_pas)
            if verification_msg == 'User Verified':
                user_mail = admin_mail
                session['user'] = user_mail
                return redirect('/admin_dashboard')
            elif verification_msg == 'Incorrect Password':
                flash(message=verification_msg, category='Error')

            elif verification_msg == 'No Data Found, Invalid credentials':
                flash(message=verification_msg, category='Error')
    return render_template('adminlogin.html')


@app.route('/quiz-start/')
# @login_req
def quiz():
    if g.user:
        try:
            name = userLogged['Name']
            if lscore[8]>=100 and not os.path.exists(f"static/certificates/{name}.png"):
                certificate_gen()
            return render_template('quizhome.html', sc=lscore)
        except Exception as e:
            print(e)
            return redirect('/error')
    else:
        return redirect("/error")


@app.route('/quiz-start/<int:id>/<int:qno>', methods=['GET', 'POST'])
# @login_req
def questions(id, qno):

    global score
    global lscore
    global r_list
    if g.user:
        if flag:
            user_answer = {'0': 'A', '1': 'B', '2': 'C', '3': 'D'}
            data = pd.read_excel('./ques_set_cleaned.xlsx')

            data.index = np.arange(1, len(data)+1)

            q_id = data.at[qno, 'Q.ID']

            question = data.at[qno, 'Questions']
            options = data.at[qno, 'Options']
            options = options.split('\n')
            Answer = data.at[qno, 'Answers']
            qset = (q_id, question, options, Answer)

            if request.method == 'POST':
                try:
                    selected_option = request.form.get('opt')
                    if user_answer[selected_option] == Answer.split()[-1]:
                        score = score + 10

                    if len(r_list) == 0:
                        try:
                            lscore[(g_id//15)] = score
                            return redirect("/score")
                        except Exception as e:
                            print(e)
                            return redirect('/error')
                    return redirect(f'/quiz-start/{id}/{r_list.pop(0)}')
                except Exception as e:
                    print(e)
            return render_template('set1.html', qset=qset)
        else:
            return redirect("/quiz-start")
    else:
        return redirect("/error")


@app.route('/quiz-start1/<int:id>/<int:qno>', methods=['GET', 'POST'])
def s_home(id, qno):
    global r_list
    global score
    global g_id
    global flag
    g_id = id
    r_list = [i for i in range(id, 15+id)]
    score = 0
    flag = True
    if g.user:
        random.shuffle(r_list)
        return redirect(f'/quiz-start/{id}/{r_list.pop(0)}')
    else:
        return redirect("/error")


@app.route('/score')
def score1():
    global flag
    if g.user:
        if flag:
            try:
                project_key = get_key(
                    key_to_get="Project_Key", dotenv_path=".env")
                deta = Deta(project_key=project_key)
                database = deta.Base('login_data')
                database.update(key=user_mail, updates={'score': lscore})
                flag = False
                return render_template('score.html', sc=score)
            except Exception as e:
                print(e)
                return redirect('/error')
        else:
            return redirect("/quiz-start")
    else:
        return redirect("/error")


@app.route('/admin_dashboard/')
def dashboard():
    if g.user:
        try:
            ssl._create_default_https_context = ssl._create_unverified_context
            project_key = get_key(key_to_get="Project_Key", dotenv_path=".env")
            deta = Deta(project_key=project_key)
            database = deta.Base("login_data")
            query = database.fetch().items
            df = pd.DataFrame(query)
            df = df[['key', 'Name', 'score']]
            df.rename(columns={'key': 'Email'}, inplace=True)

            df_table = df.to_dict()

        except Exception as e:
            print(e)

        return render_template('admin_dashboard.html', q=df_table, zip=zip)
    else:
        return redirect("/error")


def certificate_gen():

    name = userLogged['Name']
    font_path = "static/The Beauty Blink TTF.ttf"
    certificate = "static/certificate.png"
    img = Image.open(certificate, mode='r')
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(
        font_path,
        120
    )
    
    draw.text((790, 660),
              name, (0, 0, 0),
              font=font, align='right')
    img.save("static/certificates/{}.png".format(name))
   



@app.route('/static/certificates/')
def coupons():
    try:
        name = userLogged['Name']
        return render_template('cert.html', n="{}.png".format(name))
    except Exception as e:
        print(e)
        return redirect('/error')


if __name__ == '__main__':
    app.run(debug=True)
