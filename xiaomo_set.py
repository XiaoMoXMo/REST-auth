import os
from flask import Flask, make_response,jsonify,request,g
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from passlib.apps import custom_app_context as pwd_context
from flask_httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

auth = HTTPBasicAuth()


app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SQLALCHEMY_DATABASE_URI'] =\
'sqlite:///'+'data.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'xiaomo_secret_key'
app.debug = True
db = SQLAlchemy(app)
manager = Manager(app)


def response(code=0,msg='',data=None):
	return jsonify({'code':code,'msg':msg,'data':data}),code


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration = 600):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        # print('s',s)
        # print('token',s.dumps({ 'id': self.id }))
        return s.dumps({ 'username': self.username })

    def __repr__(self):
    	return '<User username=%s>' % self.username

    @staticmethod
    def verify_auth_token(token):
        print('call verify_auth_token')
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None,501 # valid token, but expired
        except BadSignature:
            return None,500 # invalid token
        print(data)
        user = User.query.filter_by(username=data.get('username')).first()
        return user,200

# @auth.verify_password
# def verify_password(username_or_token,password):
#     # first try to authenticate by token
#     print('username_or_token',username_or_token,'password',password)

#     user = User.verify_auth_token(username_or_token)
#     if not user:
#         # try to authenticate with username/password
#         user = User.query.filter_by(username = username_or_token).first()
#         if not user or not user.verify_password(password):
#             return False
#     g.user = user
#     return True


@app.errorhandler(404)
def not_found(error):
	return response(code=404,msg='not find')

# router
@app.route('/api/test')
def hello():
	token = request.args.get('token')
	if not token:
		return response(code=400,msg='token is null')
	user,code = User.verify_auth_token(token)
	if code == 200:
		return response(code=200,msg='测试接口',data={'user':user.__repr__()})
	else:
		return response(code=code,msg='erroe',data=None)

@app.route('/api/users',methods=['POST'])
def register():
    username = request.args.get('username')
    password = request.args.get('password')

    if username is None or password is None:
    	response(code=400,msg='missing arguments')
        # abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        response(code=400,msg="existing user")
        # abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return response(code=201,msg='注册成功',data={'username':user.username}), {'Location': url_for('get_user', id = user.id, _external = True)}

# @app.route('/api/resource')
# @auth.login_required
# def get_resource():
# 	print(g.user)
# 	return response(code=200,msg='resource show',data={'data':'Hello, %s!' % g.user.username })


# @app.route('/api/token')
# @auth.login_required
# def get_auth_token():
#     print('call /api/token')
#     token = g.user.generate_auth_token()
#     return response(code=200,msg='get token success',data={ 'token': token.decode('ascii') })


@app.route('/api/login')
def login():
	username = request.args.get('username')
	password = request.args.get('password')
	if not username or not password:
		return response(code=500,msg='null value')

	print(username)
	user = User.query.filter_by(username=username).first()
	print(user)
	if user:
		if user.verify_password(password):
			# g.user = user
			return response(code=200,msg='login success',data={'token':user.generate_auth_token().decode('ascii')})
		else:
			return response(code=500,msg='password or accounnt wrong 2')
	else:
		return response(code=500,msg='password or accounnt wrong 1')





@manager.shell
def make_shell_context():
	return dict(app=app,db=db,User=User,g=g)





if __name__ == "__main__":
	manager.run()
	# print('hello world')