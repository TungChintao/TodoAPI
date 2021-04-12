import os
import jwt
import time
import redis
from sqlalchemy import or_
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask import Flask, abort, request, jsonify, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=3600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


class Todo(db.Model):
    __tablename__ = 'todolist'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(60))
    content = db.Column(db.Text)
    establish = db.Column(db.String(25), default=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    deadline = db.Column(db.String(30))
    done = db.Column(db.Boolean, default=False)

    def __init__(self, title, content, deadline, user_id):
        self.title = title
        self.content = content
        self.establish = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.deadline = deadline
        self.done = False

    def task_to_json(self):
        """
        将data转换为json格式
        :return: json格式的数据
        """
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "establish": self.establish,
            "deadline": self.deadline,
            "done": self.done
        }

    @classmethod
    def tasks_to_json(cls, data):
        """
        将列表中所有数据元素转为json格式
        """
        return [t.task_to_json() for t in data]


def make_resp(data, status=200, message="success"):
    """
    自定义请求的反馈响应
    :param data: 数据
    :param status: 状态码 200代表正常/成功
    :param message: 错误信息
    """
    return {
        "status": status,
        "message": message,
        "data": data
    }


def get_redis_connection():
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    return r


def set_history(task_id):
    conn = get_redis_connection()
    history = "history_%s" % str(g.user.id)
    conn.lrem(history, 0, task_id)
    conn.lpush(history, task_id)
    conn.ltrim(history, 0, 9)


@app.route('/todo/api/v1.0/history')
@auth.login_required
def get_history():
    conn = get_redis_connection()
    history = "history_%s" % str(g.user.id)
    tasks_id = conn.lrange(history, 0, 9)
    tasks_res = list()
    for id in tasks_id:
        task = Todo.query.filter_by(id=id).first()
        tasks_res.append(task)
    return make_resp(Todo.tasks_to_json(tasks_res))


@app.errorhandler(400)
def bad_request(error):
    """400错误响应"""
    return make_resp('', 400, 'Bad Request')


@app.errorhandler(404)
def not_found(error):
    """404错误响应"""
    return make_resp('', 404, 'Not Found')


@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    print(g.user.id)
    return True


@app.route('/todo/api/v1.0/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)      # 没有用户名或密码
    if User.query.filter_by(username=username).first() is not None:
        abort(400)      # 用户已存在
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _extername=True)}


@app.route('/todo/api/v1.0/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/todo/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(3600)
    return jsonify({'token': token, 'duration': 3600})


@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
@auth.login_required
def operate_task(task_id):
    task = Todo.query.get(task_id)

    # 查看一条事项
    if request.method == 'GET':
        set_history(task_id)
        data = task.task_to_json()
        return make_resp(data)

    # 将一条待办/已完成事项设置为已完成/待办
    if request.method == 'PUT':
        task.done = not task.done
        db.session.commit()
        return make_resp(task.task_to_json())

    # 删除一条事项
    if request.method == 'DELETE':
        db.session.delete(task)
        db.session.commit()
        return make_resp({})


@app.route('/todo/api/v1.0/tasks', methods=['GET', 'POST', 'DELETE'])
@auth.login_required
def operate_tasks():
    # 查看所有事项
    if request.method == 'GET':
        search = request.args.get('search')
        page = int(request.args.get('page', 1))
        if search is None:
            data = Todo.query.paginate(page, 2).items
        else:
            data = Todo.query.filter(or_(Todo.title.contains(search), Todo.content.contains(search), Todo.deadline.contains(search), Todo.establish.contains(search))).paginate(page, 2).items
            for d in data:
                set_history(d.id)
        data = Todo.tasks_to_json(data)
        response = make_resp(data)
        return response

    # 添加一条待办事项
    if request.method == 'POST':
        if not request.json or not 'title' in request.json:
            abort(400)
        title = request.json['title']
        content = request.json.get('content', "")
        deadline = request.json.get('deadline', None)
        new = Todo(title=title, content=content, deadline=deadline)
        db.session.add(new)
        db.session.commit()
        todo = Todo.query.filter_by(title=title).first()
        data = todo.task_to_json()
        response = make_resp(data)
        return response

    # 删除所有事项
    if request.method == 'DELETE':
        tasks = Todo.query.filter_by(user_id=g.user.id).all()
        for task in tasks:
            db.session.delete(task)
        db.session.commit()
        return make_resp({})


@app.route('/todo/api/v1.0/tasks/active', methods=['GET', 'PUT', 'DELETE'])
@auth.login_required
def operate_active_tasks():
    tasks = Todo.query.filter_by(done=False).all()

    # 查看所有待办事项
    if request.method == 'GET':
        data = Todo.tasks_to_json(tasks)
        response = make_resp(data)
        return response

    # 将所有待办事项设置为已完成
    if request.method == 'PUT':
        for task in tasks:
           task.done = True
        db.session.commit()
        return make_resp({})

    # 删除所有待办事项
    if request.method == 'DELETE':
        for task in tasks:
            db.session.delete(task)
        db.session.commit()
        return make_resp({})


@app.route('/todo/api/v1.0/tasks/completed', methods=['GET', 'PUT', 'DELETE'])
@auth.login_required
def operate_completed_tasks():
    tasks = Todo.query.filter_by(done=True).all()

    # 查看所有已完成事项
    if request.method == 'GET':
        data = Todo.tasks_to_json(tasks)
        response = make_resp(data)
        return response

    # 将所有已完成事项设置为待办
    if request.method == 'PUT':
        for task in tasks:
           task.done = False
        db.session.commit()
        return make_resp({})

    # 删除所有已完成事项
    if request.method == 'DELETE':
        for task in tasks:
            db.session.delete(task)
        db.session.commit()
        return make_resp({})


@app.route('/todo/api/v1.0/tasks/number', methods=['GET'])
@auth.login_required
def get_number():
    """获取所有事项的数目"""
    data = {
        "tasks_number": Todo.query.count()
    }
    return make_resp(data)


@app.route('/todo/api/v1.0/tasks/number/completed', methods=['GET'])
@auth.login_required
def get_completed_number():
    """获取已完成事项的数目"""
    data = {
        "completed_number": Todo.query.filter_by(done=True).count()
    }
    return make_resp(data)


@app.route('/todo/api/v1.0/tasks/number/active', methods=['GET'])
@auth.login_required
def get_active_number():
    """获取待办事项数目"""

    data = {
        "completed_number": Todo.query.filter_by(done=False).count()
    }
    return make_resp(data)


if __name__ == '__main__':
    # if not os.path.exists('db.sqlite'):
    db.create_all()
    app.run(debug=True)
