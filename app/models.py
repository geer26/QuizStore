import json
from app import db, login
import bcrypt
from datetime import datetime
from flask_login import UserMixin


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


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


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, index=True, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    email = db.Column(db.String(), unique=True)
    is_superuser = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128), default='')
    salt = db.Column(db.String(128), default='')

    created = db.Column(db.DateTime(), default=datetime.now())
    last_modified = db.Column(db.DateTime(), default=datetime.now())


    def __repr__(self):
        return f'USER: {self.username}, '


    def set_password(self, password):
        salt = bcrypt.gensalt(14)
        p_bytes = password.encode()
        pw_hash = bcrypt.hashpw(p_bytes, salt)
        self.password_hash = pw_hash.decode()
        self.salt = salt.decode()
        return True


    def check_password(self, password):
        c_password = bcrypt.hashpw(password.encode(), self.salt.encode()).decode()
        if c_password == self.password_hash:
            return True
        else:
            return False


    def dump(self):
        data = {'id': self.id, 'username': self.username, 'email': self.email, 'is_superuser': self.is_superuser,
                'password_hash': self.password_hash,
                'salt': self.salt, 'created': self.created.timestamp(),
                'last_modified': self.last_modified.timestamp()}
        return json.dumps(data)

