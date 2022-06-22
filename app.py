# -*- coding: utf-8 -*-
# @Time     : 2022/6/20 14:49
# @Author   : WZS
# @File     : app.py
# @Software : PyCharm
# @Function :

from flask import Flask, redirect, url_for, render_template, request, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import pymysql

app = Flask(__name__)  # 初始化Flask app
app.secret_key = 'WZS_say_hello_to_Flask'

loginManager = LoginManager()  # 初始化一个LoginManager类对象
loginManager.login_view = 'login'  # 默认登录视图
loginManager.refresh_view = 'login'
loginManager.login_message = 'Please login first!'
loginManager.needs_refresh_message = 'Refresh for login!'
loginManager.session_protection = 'basic'
loginManager.init_app(app)  # loginManager绑定到当前app

DICT_appId = {'SearchUser': '0001', 'ModifySpecialAuthority': '0004'}
ADMIN = '000000'  # 管理员ID
HOST = 'localhost'
DB = 'AuthProject'
USER = 'auth_project'
PASSWD = '123456'
PORT = 3306


# 定义 User 类，从 UserMixin 类继承
class User(UserMixin):
    pass


def sql_query(sql):
    """
    数据库查询
    :param sql: 查询语句
    :return: 查询结果
    """
    res = []
    try:
        db = pymysql.connect(host=HOST, db=DB, user=USER, passwd=PASSWD, port=PORT)
        cursor = db.cursor()
        cursor.execute(sql)
        res = cursor.fetchall()
        cursor.close()
    except:
        print("数据库查询失败！")
    return res


def sql_modify(sql):
    """
    数据库修改
    :param sql: 修改语句
    :return:
    """
    try:
        db = pymysql.connect(host=HOST, db=DB, user=USER, passwd=PASSWD, port=PORT)
        cursor = db.cursor()
        cursor.execute(sql)
        db.commit()
        cursor.close()
    except:
        print("数据库查询失败！")


def query_user(userId):
    """
    根据ID检查用户是否存在，若存在则返回数据库中存储的该用户对应口令
    :param userId: 用户ID
    :return: 用户ID及其口令
    """
    sql = "select user_id,password from login where user_id=" + userId
    res = sql_query(sql)
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
def login(flag=None):
    """
    用户（管理员/普通用户）登录
    :return:
    """
    if request.method == 'GET':
        return render_template('login.html', flag='1')
    if request.method == 'POST':
        userId = request.form['userId']
        user = query_user(userId)
        if user is None:  # 用户不存在
            return render_template('login.html', info="alert_1", flag=flag)
        if request.form['password'] == user['password']:
            curUser = User()
            curUser.id = userId
            login_user(curUser)  # 通过Flask-Login的login_user方法登录用户
            if userId == ADMIN:  # Admin login
                return redirect(url_for('admin_main_page'))
            else:  # User login
                return redirect(url_for('user_main_page', ID=userId))
        else:  # 密码错误
            return render_template('login.html', info="alert_2", flag=flag)


@app.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    """
    用户登出
    :return:
    """
    if request.method == 'POST':
        logout_user()
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


def check_app_accessibility(userId, appId):
    """
    查询用户对某个app的使用权。如果数据库查询有结果，说明该用户对该app具备访问权。
    :return: 是否具备使用权
    """
    # 0. 确定用户所属角色和所属组
    sql = "select group_id,role_id from user_authority where user_id='{0}';".format(userId)
    res = sql_query(sql)
    userRole = res[0][1]
    userGroup = res[0][0]

    # 1. 检查用户所属角色是否对app具备访问权
    sql = "select * from app_role_rule where app_id='{0}' and role_id='{1}';".format(appId, userRole)
    res = sql_query(sql)
    if len(res) != 0:
        return True

    # 2. 检查用户所属组是否对app具备访问权
    sql = "select * from app_group_rule where app_id='{0}' and group_id='{1}';".format(appId, userGroup)
    res = sql_query(sql)
    if len(res) != 0:
        return True

    # 3. 检查用户是否对app具备特别访问权
    sql = "select * from app_user_rule where app_id='{0}' and user_id='{1}';".format(appId, userId)
    res = sql_query(sql)
    if len(res) != 0:
        return True

    # 如果按任意规则用户均不具备对app的访问权
    return False


@app.route('/app/search_user/', methods=['GET', 'POST'])
@login_required
def app_search_user():
    """
    （具备权限的用户）可以查询用户的基本信息
    :return:
    """
    if request.method == 'GET':
        if not check_app_accessibility(current_user.id, DICT_appId['SearchUser']):
            return render_template('caution.html', info='WARNING: Access denied! It seems that you do NOT have '
                                                        'permission to access the SEARCH_USER app.')
        return render_template('search_user.html', flag='0', user=current_user.id)  # flag=0不显示表格
    if request.method == 'POST':
        searchKeyword = request.form['searchKeyword']
        # 此处支持模糊搜索
        sql = "select user_id,name,nickname,phone,email,description " \
              "from user_info " \
              "where user_id='{0}' or ((select LOCATE('{0}',name))!=0) or ((select LOCATE('{0}',nickname))!=0)".format(searchKeyword)
        res = sql_query(sql)
        return render_template('search_user.html', flag='1', res=res, lres=len(res), keyword=searchKeyword, user=current_user.id)


@app.route('/app/modify_special_authority/', methods=['GET', 'POST'])
@login_required
def app_modify_special_authority():
    """
    （管理员）可以修改用户的权限
    :return:
    """
    if request.method == 'GET':
        if not check_app_accessibility(current_user.id, DICT_appId['ModifySpecialAuthority']):
            return render_template('caution.html', info='WARNING: Access denied! It seems that you do NOT have '
                                                        'permission to access the MODIFY_SPECIAL_AUTHORITY app.')
        return render_template('modify_special_authority.html')
    if request.method == 'POST':
        searchKeyword = request.form['searchKeyword']
        # 此处支持模糊搜索
        sql = "select user_id,name,nickname,phone,email,description " \
              "from user_info " \
              "where user_id='{0}'".format(searchKeyword)
        res = sql_query(sql)
        if len(res) == 0:  # 未搜索到用户
            return render_template('modify_special_authority.html', flag='-1')
        return render_template('modify_special_authority.html', flag='1', keyword=searchKeyword, res=res)  # 搜索到用户，展示


@app.route('/app/modify_special_authority/<ID>/', methods=['GET', 'POST'])
@login_required
def app_modify_special_authority_modify(ID=None):
    if request.method == 'POST':
        if ID is not None:
            sql = "select user_id,name,nickname,phone,email,description " \
                  "from user_info " \
                  "where user_id='{0}'".format(ID)
            res = sql_query(sql)
            sql = "select app_id,app_name from app_info;"
            appres = sql_query(sql)
            return render_template('modify_special_authority.html', flag='2', keyword=ID, res=res, appres=appres, lenappres=len(appres))  # 搜索到用户，展示


@app.route('/app/modify_special_authority/<ID>/implement/', methods=['GET', 'POST'])
@login_required
def app_modify_special_authority_implement(ID=None):
    if request.method == 'POST':
        if ID is not None:
            appId = request.form['appSelect']
            userId = ID
            rule = request.form['ruleSelect']
            if rule == 'permit':
                sql = "select max(app_user_rule_id) from app_user_rule";
                res = sql_query(sql)
                if res[0][0] is None:  # 空表
                    maxRuleId = 0
                else:
                    maxRuleId = res[0][0]
                sql = "insert into app_user_rule(app_user_rule_id,app_id,user_id) values ({0},'{1}','{2}');".format(maxRuleId+1, appId, userId)
                print(appId, rule, userId, maxRuleId, sql)
                sql_modify(sql)
                return render_template('modify_special_authority.html', flag='3', keyword=ID, appId=appId)
            elif rule == 'deny':
                sql = "delete from app_user_rule where app_id='{0}' and user_id='{1}';".format(appId, userId)
                sql_modify(sql)
                return render_template('modify_special_authority.html', flag='4', keyword=ID, appId=appId)


if __name__ == "__main__":
    app.debug = True  # 实时调试
    app.run()  # 启动
