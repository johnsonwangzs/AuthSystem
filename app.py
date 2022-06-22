# -*- coding: utf-8 -*-
# @Time     : 2022/6/20 14:49
# @Author   : WZS
# @File     : app.py
# @Software : PyCharm
# @Function :

from flask import Flask, redirect, url_for, render_template, request, flash
from flask_login import LoginManager, login_manager, UserMixin, login_required, login_user, logout_user, current_user
import pymysql

app = Flask(__name__)  # 初始化Flask app
app.secret_key = 'Hello, Flask!'
loginManager = LoginManager()  # 初始化一个LoginManager类对象
loginManager.login_view = 'login'  # 默认登录视图
loginManager.refresh_view = 'login'
loginManager.login_message = 'Please login first!'
loginManager.needs_refresh_message = 'Refresh for login!'
loginManager.session_protection = 'basic'

loginManager.init_app(app)  # loginManager绑定到当前app

DICT_appId = {'search_user': '0001'}
ADMIN = '000000'  # 管理员ID


# 定义 User 类，从 UserMixin 类继承
class User(UserMixin):
    pass


def query_user(userId):
    """
    根据ID检查用户是否存在，若存在则返回数据库中存储的该用户对应口令
    :param userId: 用户ID
    :return: 用户ID及其口令
    """
    res = []
    try:
        db = pymysql.connect(host='localhost', db='AuthProject', user='auth_project', passwd='123456', port=3306)
        cursor = db.cursor()
        sql = "select user_id,password from login where user_id=" + userId
        cursor.execute(sql)
        res = cursor.fetchall()
        cursor.close()
    except:
        print("数据库查询失败！")
    if len(res) == 0:
        return None
    else:
        userDict = {'userId': res[0][0], 'password': res[0][1]}
        return userDict


@loginManager.user_loader
def load_user(userId):
    """
    user_loader 回调函数
    :param userId: user session记录的用户ID
    :return: userId对应的User对象
    """
    if query_user(userId) is not None:
        curUser = User()
        curUser.id = userId
        return curUser
    return None


@app.route('/')
@app.route('/login/', methods=['GET', 'POST'])
def login():
    """
    用户（管理员/普通用户）登录
    :return:
    """
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        userId = request.form['userId']
        user = query_user(userId)
        if user is None:  # 用户不存在
            return render_template('login.html', info="alert_1")
        if request.form['password'] == user['password']:
            curUser = User()
            curUser.id = userId
            login_user(curUser)  # 通过Flask-Login的login_user方法登录用户
            if userId == ADMIN:  # Admin login
                return redirect(url_for('admin_main_page'))
            else:  # User login
                return redirect(url_for('user_main_page', ID=userId))
        else:  # 密码错误
            return render_template('login.html', info="alert_2")


@app.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    """
    用户登出
    :return:
    """
    if request.method == 'POST':
        logout_user()
        flash('User logout')
        return redirect(url_for('login'))


@app.route('/upload/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        f = request.files['']
        f.save('./files/')


@app.route('/user_main/')
@app.route('/user_main/<ID>/')
@login_required
def user_main_page(ID=None):
    """
    显示普通用户主页
    :param ID:
    :return:
    """
    if current_user.id != ID:  # 当前用户试图访问其他用户的网页，属于非法访问
        return render_template('caution.html', info='WARNING: You do NOT have permission to view other user\'s pages!')
    if current_user.id == ADMIN:
        return redirect(url_for('admin_main_page'))
    return render_template('user_main.html', userId=current_user.id)


@app.route('/admin_main/', methods=['GET', 'POST'])
@login_required
def admin_main_page():
    """
    显示管理员主页
    :return:
    """
    if request.method == 'GET':
        if current_user.id != ADMIN:  # 普通用户试图通过URL访问admin页面，视为非法访问
            return render_template('caution.html', info='WARNING: Access denied! You are NOT Admin.')
        return render_template('admin_main.html', userId=current_user.id)
    if request.method == 'POST':
        return redirect(url_for('logout'))


def check_app_rule(userId, appId):
    """
    查询用户对某个app的使用权
    :return: 是否具备使用权
    """
    return True


@app.route('/search/', methods=['GET', 'POST'])
@login_required
def app_search_user():
    """
    查询用户的app
    :return:
    """
    if request.method == 'GET':
        if not check_app_rule(current_user.id, DICT_appId['search_user']):
            return render_template('caution.html', info='WARNING: Access denied! It seems that you do NOT have '
                                                        'permission to access the SEARCH_USER app.')
        return render_template('search_user.html')
    # if request.method == 'POST':


@app.route('/modify/')
@login_required
def user_modify_page():
    """
    普通用户修改个人信息
    :return:
    """
    return render_template('modify.html')


if __name__ == "__main__":
    app.debug = True  # 实时调试
    app.run()  # 启动
