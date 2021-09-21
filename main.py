import hashlib
import os
import uuid as uuid
from base64 import b64encode, b64decode
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import UUID
from dotenv import load_dotenv

from flask_jwt_extended import create_access_token, get_jwt, set_access_cookies, unset_jwt_cookies
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'postgresql+pg8000://' + os.getenv('POSTGRES_USER') + \
    ':' + os.getenv('POSTGRES_PASSWORD') + '@' + \
    os.getenv('POSTGRES_HOST') + '/' + os.getenv('POSTGRES_DB')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('APP_SECRET_KEY')

# JWT settings
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # production
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]  # non-production
app.config['CORS_HEADERS'] = 'Content-Type'

# required for development
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

CHARSET = "UTF-8"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), default=uuid.uuid4)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    password = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default="now()")
    updated = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username


class Notebook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), default=uuid.uuid4)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default="now()")
    updated = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.DateTime, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('notebooks', lazy=True))

    def to_json(self):
        return {
            "uuid": str(self.uuid),
            "name": self.name,
            "description": self.description,
            "created": str(self.created),
        }


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), default=uuid.uuid4)
    created = db.Column(db.DateTime, nullable=False, default="now()")
    updated = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.DateTime, nullable=True)

    notebook_id = db.Column(db.Integer, db.ForeignKey('notebook.id'), nullable=False)
    notebook = db.relationship('Notebook', backref=db.backref('notebooks', lazy=True, cascade='all, delete-orphan'))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('notes', lazy=True))

    def to_json(self, message):
        return {
            "uuid": str(self.uuid),
            "message": message,
            "created": str(self.created),
            "user_id": str(self.user.uuid),
        }


def hash_password(value):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        value.encode('utf-8'),
        salt,
        100000,
    )

    return b64encode(salt).decode("utf-8") + b64encode(key).decode("utf-8")


def verify_password(check, password):
    salt = b64decode(password[:44])
    key = b64decode(password[44:])

    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        check.encode('utf-8'),
        salt,
        100000,
    )

    return new_key == key


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def get_notebook_by_notebook_id(notebook_id):
    return Notebook.query.filter_by(uuid=notebook_id).first()


def upload_note_to_s3(note_id, message):
    s3_client = boto3.client('s3')
    s3_client.put_object(Body=message, Bucket=os.getenv("AWS_BUCKET"), Key=note_id)


def get_note_from_s3(note_id):
    s3_client = boto3.client('s3')
    try:
        return s3_client.get_object(Bucket=os.getenv("AWS_BUCKET"), Key=note_id)['Body'].read().decode("utf-8")
    except ClientError:
        pass


@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


@app.route("/")
def home():
    return "<p>Hello, World!</p>"


@app.route("/version")
def version():
    return "v0.1"


@app.route("/contact", methods=["POST"])
def contact():
    client = boto3.client('ses', region_name=os.getenv("AWS_REGION"))
    data = request.get_json(force=True)
    try:
        client.send_email(
            Destination={
                'ToAddresses': [
                    'dan@danmunro.com',
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': """<html>
<head></head>
<body>
  <p>{message}</p>
</body>
</html>""".format(message=data['message']),
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': data['message'],
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': "Note Goat Contact",
                },
            },
            Source=os.getenv("CONTACT_EMAIL"),
            ReplyToAddresses=[
                data['email'],
            ],
        )
        return jsonify({"message": "success"})
    except ClientError as e:
        print(e.response['Error']['Message'])
        return jsonify({"message": "failure"}), 500


@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json(force=True)
    try:
        user = User(username=data['username'], password=hash_password(data['password']))
        db.session.add(user)
        db.session.commit()
        return {"uuid": str(user.uuid)}
    except IntegrityError:
        return "", 400


@app.route("/verification", methods=["POST"])
def verify_user():
    pass


@app.route("/session", methods=["POST"])
def create_session():
    data = request.get_json(force=True)
    user = get_user_by_username(data['username'])
    if verify_password(data['password'], user.password):
        access_token = create_access_token(identity=user.username)
        response = jsonify({
            "message": "success",
            "access_token": access_token,
        })
        set_access_cookies(response, access_token)
        return response
    return "", 403


@app.route("/session", methods=["DELETE"])
def delete_session():
    response = jsonify({"message": "logout successful"})
    unset_jwt_cookies(response)
    return response


@app.route("/session")
@jwt_required()
def get_session():
    token = get_jwt_identity()
    return {"loggedIn": True if token else False}, 200


@app.route("/notebook/<notebook_id>/note")
@jwt_required()
def get_all_notes_for_notebook(notebook_id):
    token = get_jwt_identity()
    notebook = get_notebook_by_notebook_id(notebook_id)
    user = get_user_by_username(token)
    if notebook is None or notebook.user_id != user.id:
        return "", 404
    return jsonify({
        "notes": list(
            map(
                lambda x:
                x.to_json(get_note_from_s3(str(x.uuid))),
                Note.query.filter_by(notebook_id=notebook.id).order_by(Note.created.desc()).all(),
            )
        )}), 200


@app.route("/notebook/<notebook_id>/note", methods=["POST"])
@jwt_required()
def create_note(notebook_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    data = request.get_json(force=True)
    notebook = get_notebook_by_notebook_id(notebook_id)
    if notebook is None or notebook.user_id != user.id:
        return "", 404
    note = Note(
        notebook=notebook,
        user=user,
    )
    db.session.add(note)
    db.session.commit()
    upload_note_to_s3(str(note.uuid), data["message"])
    return note.to_json(data["message"])


@app.route("/note/<note_id>", methods=["PUT"])
@jwt_required()
def update_note(note_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    data = request.get_json(force=True)
    note = Note.query.filter_by(
        uuid=note_id,
        user_id=user.id,
    ).first()
    if note is None:
        return "", 404
    upload_note_to_s3(str(note.uuid), data["message"])
    return note.to_json(data["message"])


@app.route("/note/<note_id>")
@jwt_required()
def get_note(note_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    note = Note.query.filter_by(
        uuid=note_id,
        user_id=user.id,
    ).first()
    if note is None:
        return "", 404
    return note.to_json(get_note_from_s3(str(note.uuid)))


@app.route("/note/<note_id>", methods=["DELETE"])
@jwt_required()
def delete_note(note_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    note = Note.query.filter_by(
        uuid=note_id,
        user_id=user.id,
    ).first()
    if note is None:
        return "", 404
    db.session.delete(note)
    db.session.commit()
    return "", 200


@app.route("/notebook")
@jwt_required()
def get_all_notebooks():
    token = get_jwt_identity()
    user = get_user_by_username(token)
    return jsonify(list(map(lambda x: x.to_json(), Notebook.query.filter_by(user_id=user.id).order_by(Notebook.created.desc())))), 200


@app.route("/notebook/<notebook_id>")
@jwt_required()
def get_notebook(notebook_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    notebook = Notebook.query.filter_by(
        uuid=notebook_id,
        user_id=user.id,
    ).first()
    if notebook is None:
        return "", 404
    return jsonify(notebook.to_json())


@app.route("/notebook/<notebook_id>", methods=["PUT"])
@jwt_required()
def update_notebook(notebook_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    notebook = Notebook.query.filter_by(
        uuid=notebook_id,
        user_id=user.id,
    ).first()
    if notebook is None:
        return "", 404
    data = request.get_json(force=True)
    notebook.name = data['name']
    db.session.add(notebook)
    db.session.commit()
    return jsonify(notebook.to_json())


@app.route("/notebook", methods=["POST"])
@jwt_required()
def create_notebook():
    token = get_jwt_identity()
    data = request.get_json(force=True)
    user = get_user_by_username(token)
    notebook = Notebook(
        user=user,
        name=data['name'],
        description=data['description'],
    )
    db.session.add(notebook)
    db.session.commit()
    return jsonify(notebook.to_json())


@app.route("/notebook/<notebook_id>", methods=["DELETE"])
@jwt_required()
def delete_notebook(notebook_id):
    token = get_jwt_identity()
    user = get_user_by_username(token)
    notebook = Notebook.query.filter_by(
        uuid=notebook_id,
        user_id=user.id,
    ).first()
    if notebook is None:
        return "", 404
    db.session.delete(notebook)
    db.session.commit()
    return "", 200


if __name__ == "__main__":
    app.run()
