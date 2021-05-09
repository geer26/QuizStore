import json

#from app import db, login, fernet, logger

#import bcrypt

from datetime import datetime

from flask_login import UserMixin

'''
@login.user_loader
def load_user(id):
    return User.query.get(int(id))
'''


'''
===============================
USERS
-------------------------------
 - id (int, u)
 - username (str/16/, u)
 !- description (str/64/, enc)
 !- contact (str/256/, enc)
 - is_superuser (bool)
 - password_hash (str/128/)
 - salt (str/128/)
 - settings (str/2048/, #json)
===============================
'''

'''
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, index=True, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    description = db.Column(db.LargeBinary)
    contact = db.Column(db.LargeBinary)
    is_superuser = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128), default='')
    salt = db.Column(db.String(128), default='')
    settings = db.Column(db.String(2048), default='')

    added = db.Column(db.DateTime(), default=datetime.now())
    last_modified = db.Column(db.DateTime(), default=datetime.now())

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        salt = bcrypt.gensalt(14)
        p_bytes = password.encode()
        pw_hash = bcrypt.hashpw(p_bytes, salt)
        self.password_hash = pw_hash.decode()
        self.salt = salt.decode()
        logger.upd_log(f'{self.username} changed password', 0)
        return True

    def check_password(self, password):
        c_password = bcrypt.hashpw(password.encode(), self.salt.encode()).decode()
        if c_password == self.password_hash:
            return True
        else:
            return False

    def set_description(self, desc):
        self.description = fernet.encrypt(desc.encode('utf-8'))
        return True

    def set_contact(self, contact):
        self.contact = fernet.encrypt(contact.encode('utf-8'))
        return True

    def get_description(self):
        return fernet.decrypt(self.description).decode('utf-8')

    def get_contact(self):
        return fernet.decrypt(self.contact).decode('utf-8')

    def dump(self):
        data = {'id': self.id, 'username': self.username, 'description': self.get_description(),
                'contact': self.get_contact(), 'is_superuser': self.is_superuser, 'password_hash': self.password_hash,
                'salt': self.salt, 'settings': self.settings, 'added': self.added.timestamp(),
                'last_modified': self.last_modified.timestamp()}
        return json.dumps(data)

    def load(self, data):
        data = json.loads(data)
        self.id = int(data['id'])
        self.username = str(data['username'])
        self.set_description(data['description'])
        self.set_contact(data['contact'])
        self.is_superuser = data['is_superuser']
        self.password_hash = str(data['password_hash'])
        self.salt = str(data['salt'])
        self.settings = str(data['settings'])
        self.added = datetime.fromtimestamp(data['added'])  # self.added.timestamp()
        self.last_modified = datetime.now()
        return 0
'''