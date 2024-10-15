from flask import Flask, redirect, url_for, session, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from googleapiclient.discovery import build
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message

# 加載.env文件中的環境變數
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')

# 初始化數據庫
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# 初始化 OAuth 認證
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    redirect_uri=os.getenv('GOOGLE_REDIRECT_URI'),
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/gmail.readonly'}
)

# 初始化 Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# 數據庫模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    google_id = db.Column(db.String(150), unique=True, nullable=True)

# 登入管理
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'login' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and user.password == password:
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('登入失敗，請檢查您的電子郵件和密碼。', 'error')
        
        if 'register' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')
            if User.query.filter_by(email=email).first():
                flash('該郵箱已註冊。', 'error')
            else:
                new_user = User(email=email, password=password)
                db.session.add(new_user)
                db.session.commit()
                flash('註冊成功！', 'success')
                login_user(new_user)
                return redirect(url_for('dashboard'))
        
    return render_template('index.html')

@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize(redirect_uri=redirect_uri)

@app.route('/auth/callback')
def google_auth():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    google_id = user_info['sub']
    
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User(email=user_info['email'], google_id=google_id)
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', email=current_user.email)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(user.email, '重置密碼', f'請點擊連結重置密碼：{reset_url}')
            flash('已發送重置密碼的郵件', 'success')
        else:
            flash('該郵箱尚未註冊。', 'error')
    return render_template('forgot_password.html')

def generate_reset_token(email):
    # 這裡可以使用其餘方法生成安全的 token
    return 'token'

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form.get('password')
        # 根據 token 查詢用戶並重設密碼
        flash('密碼已成功重置。', 'success')
        return redirect(url_for('index'))
    return render_template('reset_password.html')

def send_email(to, subject, body):
    msg = Message(subject, sender=os.getenv('MAIL_USERNAME'), recipients=[to])
    msg.body = body
    mail.send(msg)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,port=10000, host='0.0.0.0')
