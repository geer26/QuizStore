from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from .config import SQLite, PostgreSQL
from flask_socketio import SocketIO
import os


app = Flask(__name__)

dbtype = os.environ.get('DB_TYPE')
if dbtype == 'sqlite':
    app.config.from_object(SQLite)
elif dbtype == 'pgdb':
    app.config.from_object(PostgreSQL)
else:
    raise RuntimeError('Database URI exception!')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

with app.app_context():
    if db.engine.url.drivername == 'sqlite':
        migrate.init_app(app, db, render_as_batch=True)
    else:
        migrate.init_app(app, db)


'''
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
'''

login = LoginManager(app)

#socket = SocketIO(app)
#socket.init_app(app, cors_allowed_origins="*")


from app import routes, models