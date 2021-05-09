from flask import render_template, jsonify
#from flask_login import current_user, login_user, logout_user, login_required
from app import app #limiter
#from app.models import User


@app.route('/')
@app.route('/index')
#@limiter.limit('1/10second')
def index():
    return jsonify({'message':'Hello World!'})
