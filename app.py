import json
import os
import sqlite3

from flask import Flask, redirect, request, url_for, render_template, jsonify
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests
from google.cloud import storage
from werkzeug.utils import secure_filename


from db import init_db_command
from user import User

# Google Oauth Credentials
GOOGLE_CLIENT_ID = "710459982991-sl0sb3n3kl0s8abqe66f1ss3dt0fpgam.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "ygagrMcKZcLKKD4f_wobLntU"


GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Google Bucket Credentials

app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = '/files'
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)


credential_path = os.path.join(os.path.dirname(app.instance_path), 'cre.json')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path


try:
    init_db_command()
except sqlite3.OperationalError:
    pass

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Bucket Setup
bucket_client = storage.Client()
bucket = bucket_client.get_bucket('dogoo123')

bucket_name = 'dogoo123'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)




@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template('home.html',user_name = current_user.name, user_img = current_user.profile_pic)
    else:
        return render_template('index.html')

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]


    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)



    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    login_user(user)

    return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))





@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if request.method == "POST":

        if request.files:

            uploaded_file = request.files["customFile"]
            filename = secure_filename(uploaded_file.filename)
            print(uploaded_file)
            uploaded_file.save('files/'+filename)
            blob = bucket.blob(filename)
            blob.upload_from_filename('files/'+uploaded_file.filename)
            os.remove('files/'+filename)
            return render_template('home.html',user_name = current_user.name, user_img = current_user.profile_pic ,msg=1)
        return render_template('home.html',user_name = current_user.name, user_img = current_user.profile_pic ,msg=0)

@app.route('/upload', methods=['GET'])
@login_required
def upload_get():
    if current_user.is_authenticated:
        return render_template('home.html',user_name = current_user.name, user_img = current_user.profile_pic)
    else:
        return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)