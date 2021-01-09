import re
import uuid
from flask import Flask, request, make_response, g
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from datetime import datetime, timedelta
from redis import StrictRedis
from os import getenv
from jwt import encode, decode, InvalidTokenError
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
from flask_cors import CORS, cross_origin

REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(host=REDIS_HOST, port=20299, db=0, password=REDIS_PASS)
JWT_SECRET = getenv("JWT_SECRET")

load_dotenv()

SESSION_TYPE = 'redis'  # 'filesystem'
SESSION_REDIS = db
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
app.config['CORS_HEADERS'] = 'Content-Type'

HAL(app)


def generate_auth_token(username):
    payload = {
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=8),
        "sub": username,
        "role": 'sender'
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def allowed_methods(methods):
    if 'OPTIONS' not in methods:
        methods.append('OPTIONS')
    response = make_response('', 204)
    response.headers['Allow'] = ', '.join(methods)
    return response


@app.before_request
def before_request_func():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        g.authorization = decode(token, JWT_SECRET, algorithms=['HS256'])
    except InvalidTokenError as e:
        g.authorization = None
        print(e)
    return


# ==================================OPTIONS========================


@app.route('/', methods=['GET', 'OPTIONS'])
@cross_origin()
def root():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    links = [Link('auth', '/auth'),
             Link('labels', '/sender'),
             Link('packages', '/packages')]

    # if g.authorization is None:
    #     links.append(Link('test', '/test'))
    document = Document(data={}, links=links)
    return document.to_json()


# ==================================AUTH========================

@app.route('/auth/login/auth0', methods=['POST'])
@cross_origin(expose_headers=['Authorization'])
def auth_auth0():
    email = request.json.get('email')
    sub = request.json.get('sub')

    if user_exists(email):
        return create_message_response("Username already exists", 400)

    is_registered = db.hexists(f"auth:{email}", "sub")

    if not is_registered:
        salt = gensalt(5)
        password = sub.encode()
        hashed_sub = hashpw(password, salt)
        db.hset(f"auth0:{email}", "sub", hashed_sub)

    if not auth0_verify_user(email, sub):
        return create_message_response("Incorrect username or/and password", 400)

    token = generate_auth_token(email)
    response = make_response('', 200)
    response.headers['Authorization'] = 'Bearer ' + token.decode()
    return response


@app.route('/auth', methods=['GET', 'OPTIONS'])
@cross_origin()
def auth():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    links = [Link('register', '/auth/register'),
             Link('login', '/auth/login')]
    document = Document(data={}, links=links)
    return document.to_json()


@app.route('/auth/register', methods=["POST"])
@cross_origin()
def add_user():
    if request.method == 'OPTIONS':
        return allowed_methods(['POST'])

    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    address = request.json.get('address')
    pl = 'ąćęłńóśźż'
    PL = 'ĄĆĘŁŃÓŚŹŻ'
    if not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(firstname):
        return create_message_response("Invalid firstname", 400)
    if not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(lastname):
        return create_message_response("Invalid lastname", 400)
    if not re.compile('[a-z]{3,12}').match(username):
        return create_message_response("Invalid username", 400)
    if not re.compile('.{8,}').match(password.strip()):
        return create_message_response("Invalid password", 400)
    if not re.compile(
            '(?:[A-Za-z0-9!#$%&\'*+/=?^_`{​​|}​​~-]+(?:\\.[A-Za-z0-9!#$%&\'*+/=?^_`{​​|}​​~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){​​3}​​(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[A-Za-z0-9-]*[A-Za-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])').match(
        email.strip()):
        return create_message_response("Invalid email", 400)
    if address is None:
        return create_message_response("Empty address", 400)
    if user_exists(username):
        return create_message_response("Username already exists", 400)
    if not save_user(username, firstname, lastname, address, password, email):
        return create_message_response("An error occurred", 500)

    links = [Link('next', '/auth/login')]
    data = {'message': 'Account created'}
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/auth/login', methods=["POST"])
@cross_origin(expose_headers=['Authorization'])
def auth_login():
    if request.method == 'OPTIONS':
        return allowed_methods(['POST'])

    username = request.json.get('username')
    password = request.json.get('password')

    if not verify_user(username, password):
        return create_message_response("Incorrect username or/and password", 400)

    token = generate_auth_token(username)
    response = make_response('', 200)
    response.headers['Authorization'] = 'Bearer ' + token.decode()
    return response


# ==================================LABELS========================


@app.route('/labels', methods=['OPTIONS'])
@cross_origin()
def sender_get_labels():
    return allowed_methods(['GET', 'POST'])


@app.route('/labels', methods=["GET"])
@cross_origin(headers=['Authorization'])
def get_labels_by_sender():
    if g.authorization is None:
        return create_message_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    keys = db.keys(pattern='label*')
    data = []
    label_json = {}
    for key in keys:
        sender = db.hget(key, "sender").decode()
        if username == sender or g.authorization.get('role') == 'courier':
            label_id = key.decode().split(":")[1]
            link = Link('self', '/labels/' + label_id)
            addressee = db.hget(key, "addressee").decode()
            size = db.hget(key, "size").decode()
            po_box_id = db.hget(key, "POBoxId").decode()
            sent = db.hget(key, "sent").decode()
            label_json = {
                "id": label_id,
                "sender": sender,
                "addressee": addressee,
                "size": size,
                "poBox": po_box_id,
                "sent": sent,
            }
            data.append(Embedded(data=label_json, links=[link]))

    links = [Link('self', '/labels/{id}', templated=True)]
    document = Document(embedded={'data': Embedded(data=data)},
                        links=links)
    return document.to_json()


@app.route('/labels', methods=["POST"])
@cross_origin(headers=['Authorization'])
def add_label():
    if g.authorization is None:
        return create_message_response("Unauthorized", 401)
    sender = g.authorization.get('sub')
    size = request.json.get('size')
    addressee = request.json.get('addressee')
    po_box_id = request.json.get('POBoxId')
    if addressee is None:
        return create_message_response("Invalid addressee", 400)
    if size not in ('XS', 'S', 'M', 'L', 'XL'):
        return create_message_response("Invalid size", 400)
    if po_box_id is None:
        return create_message_response("Invalid PO box id", 400)
    label_id = uuid.uuid4()
    db.hset(f"label:{label_id}", "sender", f"{sender}")
    db.hset(f"label:{label_id}", "addressee", f"{addressee}")
    db.hset(f"label:{label_id}", "size", f"{size}")
    db.hset(f"label:{label_id}", "POBoxId", f"{po_box_id}")
    db.hset(f"label:{label_id}", "sent", "false")

    data = {"id": str(label_id),
            "sender": sender,
            "addressee": addressee,
            "size": size,
            "POBoxId": po_box_id,
            "sent": "false"}
    links = [Link('self', '/labels/' + str(label_id))]
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/labels/<label_uuid>', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def sender_get_label(label_uuid):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'PUT', 'DELETE'])
    if g.authorization is None:
        return create_message_response("Unauthorized", 401)
    if not db.hexists(f"label:{label_uuid}", "size"):
        return create_message_response("Label not Found", 404)
    username = g.authorization.get('sub')
    if not g.authorization.get('role') == 'courier' or db.hget(f"label:{label_uuid}", "sender").decode() == username:
        return create_message_response("Label not found", 404)
    receiver = db.hget(f"label:{label_uuid}", "receiver").decode()
    size = db.hget(f"label:{label_uuid}", "size").decode()
    po_box_id = db.hget(f"label:{label_uuid}", "POBoxId").decode()
    sent = db.hget(f"label:{label_uuid}", "sent").decode()
    data = {"labelId": label_uuid,
            "username": username,
            "receiver": receiver,
            "size": size,
            "POBoxId": po_box_id,
            "sent": sent}
    links = [Link('self', '/labels/' + label_uuid)]
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/labels/<label_uuid>', methods=["DELETE"])
@cross_origin(headers=['Authorization'])
def label_delete(label_uuid):
    if g.authorization is None:
        return create_message_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    if not db.hexists(f"label:{label_uuid}", "size"):
        return create_message_response("Label not Found", 404)
    if not db.hget(f"label:{label_uuid}", "sender").decode() == username:
        return create_message_response("Label not found", 404)
    db.delete(f"label:{label_uuid}")
    link = [Link('all', '/labels')]

    document = Document(embedded={'data': Embedded(data={})},
                        links=link)
    return document.to_json()


# ================================PACKAGES=============


@app.route('/packages', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def packages_get():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_message_response("Unauthorized", 401)

    keys = db.keys(pattern='package*')
    data = []
    package_json = {}
    for key in keys:
        package_id = key.decode().split(":")[1]
        link = Link('self', '/packages/' + package_id)
        status = db.hget(key, "status").decode()
        label_id = db.hget(key, "labelId").decode()
        package_json = {
            "id": package_id,
            "status": status,
            "labelId": label_id
        }
        data.append(Embedded(data=package_json, links=[link]))

    links = [Link('self', '/packages/{id}', templated=True)]
    document = Document(embedded={'data': Embedded(data=data)},
                        links=links)
    return document.to_json()


@app.route('/packages', methods=['POST'])
@cross_origin(headers=['Authorization'])
def package_create():
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_message_response("Unauthorized", 401)

    label_id = request.json.get('labelId')
    if not db.hexists(f"label:{label_id}", "size"):
        return create_message_response("Label not Found", 404)

    if not db.hget(f"label:{label_id}", "sent").decode() == 'false':
        return create_message_response("Label already sent", 400)

    db.hset(f"label:{label_id}", "sent", 'true')

    package_id = str(uuid.uuid4())

    db.hset(f"package:{package_id}", "packageId", f"{package_id}")
    db.hset(f"package:{package_id}", "labelId", f"{label_id}")
    db.hset(f"package:{package_id}", "status", "IN_TRANSIT")

    data = {"packageId": package_id,
            "labelId": label_id,
            "status": "IN_TRANSIT"}

    links = [Link('self', '/packages/{id}', templated=True)]
    document = Document(embedded={'data': Embedded(data=data)},
                        links=links)
    return document.to_json()


@app.route('/packages/<package_id>', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def package_get(package_id):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'PUT'])
    if g.authorization is None or g.authorization.get('role') == 'courier':
        return create_message_response("Unauthorized", 401)
    if not db.hexists(f"package:{package_id}", "labelId"):
        return create_message_response("Package not found", 404)

    label_id = db.hget(f"package:{package_id}", "labelId").decode()
    status = db.hget(f"package:{package_id}", "status").decode()

    data = {"packageId": package_id,
            "labelId": label_id,
            "status": status}

    links = [Link('self', '/packages/' + package_id)]
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/packages/<package_id>', methods=['PUT'])
@cross_origin(headers=['Authorization'])
def package_update(package_id):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'PUT'])
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_message_response("Unauthorized", 401)
    if not db.hexists(f"package:{package_id}", "labelId"):
        return create_message_response("Package not found", 404)

    status = request.json.get('status')
    if status not in ('IN_TRANSIT', 'DELIVERED', 'PICKED_UP'):
        return create_message_response("Invalid status", 400)

    db.hset(f"package:{package_id}", "status", status)
    label_id = db.hget(f"package:{package_id}", "labelId").decode()
    data = {"packageId": package_id,
            "labelId": label_id,
            "status": status}

    links = [Link('self', '/packages/' + package_id)]
    document = Document(data=data, links=links)
    return document.to_json()


def create_message_response(msg, status):
    response = make_response({"message": msg}, status)
    return response


def user_exists(username):
    if db.hexists(f"user:{username}", "password"):
        return True
    return False


def save_user(username, firstname, lastname, address, password, email):
    password = password.encode()
    salt = gensalt(5)
    password_hashed = hashpw(password, salt)
    db.hset(f"user:{username}", "password", password_hashed)
    db.hset(f"user:{username}", "firstname", firstname)
    db.hset(f"user:{username}", "lastname", lastname)
    db.hset(f"user:{username}", "address", address)
    db.hset(f"user:{username}", "email", email)
    return True


def verify_user(username, password):
    password = password.encode()
    hashed = db.hget(f"user:{username}", "password")
    if not hashed:
        return False

    return checkpw(password, hashed)


def auth0_verify_user(email, sub):
    password = sub.encode()
    hashed = db.hget(f"auth0:{email}", "sub")
    if not hashed:
        return False

    return checkpw(password, hashed)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)
