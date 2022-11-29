# AuthSystem
An authentication and authority management system based on Flask.

**注意，只实现了基础的功能，有些写法比较初级（如未使用蓝图，数据库操作不够模块化），且缺少安全细节（如口令存储、防范各种网页攻击等），后期有空再加。**

**建议配合https://github.com/johnsonwangzs/TestFlask食用（使用了Flask蓝图等高级用法，以及Flask-Login、Flask-wtforms等扩展）。**

---

# 使用说明
1. 将所有文件下载并保存为一个Python项目。
2. 安装Flask和Flash-Login。
3. 将db目录下的createDB.sql作为MySQL脚本导入。
4. 创建一个数据库用户，根据数据库具体配置修改app.py中用于连接数据库的常量。
5. 在app.py下运行程序，浏览器打开http://127.0.0.1:5000。
6. Enjoy yourself!

注：部分功能待实现。

---


# 用户身份认证及权限管理系统设计文档

## 1 主要功能

### 1.1 用户登录（身份认证）

根据用户id识别用户的身份：

- 管理员
- 普通用户

### 1.2 系统功能

#### 1.2.1 权限管理（管理员）

#### 1.2.2 用户信息展示



### 1.3 用户登出

点击登出按钮进行登出。

## 2 实现环境

- Web（HTML+JavaScript+Bootstrap）
- Flask+Python
- MySQL

## 3 权限系统设计

### 3.1 数据库设计

```sql
source D://CODE/Python//Code//AuthenticationAndAuthorityManagementSystem//db//createDB.sql;
source D://CODE/Python//Code//AuthenticationAndAuthorityManagementSystem//db//dropDB.sql;
```



#### 3.1.1 实体

**用户账号表user_login**（用户认证）——用于用户的登录（认证）

- user_id——用户自己不能修改
- password

**用户表user_info**（用户的基本信息）——保存用户的基本信息

- user_id
- name
- nickname
- phone
- email
- description

**组表group_info**（组信息）——多个用户可能属于一个组

- group_id
- group_name——财务处
- group_description

**角色表role_info**（角色信息）——同一个角色可能对应多个用户

- role_id
- role_name——CEO
- role_level——级别
- role_description

**应用表app_info**（应用信息）

- app_id
- app_name——报销系统
- app_description

#### 3.1.2 关系设计

**用户权限表user_authority**（用户的权限信息）——用户属于唯一的组，具有唯一的角色

- user_id
- group_id
- role_id

**应用-组许可规则app_group_rule**——决定特定组可以使用某个应用

- app_group_rule_id
- app_id
- group_id

**应用-角色许可规则app_role_rule**——决定特定角色可以使用某个应用

- app_role_rule_id
- app_id
- role_id

**应用-用户许可规则app_user_rule**——决定特定用户可以使用某个应用

- app_user_rule_id
- app_id
- user_id

**文件-组许可规则file_group_rule**——决定特定组对某个文件的访问权限

- file_group_rule_id
- file_id
- group_id
- rule——读/写/修改等权限

**文件-角色许可规则file_role_rule**——决定特定角色对某个文件的访问权限

- file_role_rule_id
- file_id
- role_id
- rule

**文件-用户许可规则file_user_rule**——决定特定用户对某个文件的访问权限

- file_user_rule_id
- dile_id
- user_id
- rule

### 3.2 用户权限逻辑

**应用规则**决定特定组（app_group_rule)、特定角色（app_role_rule）、特定用户（app_user_rule）能够使用某个应用。

**文件规则**决定特定组、特定角色、特定用户对某项文件资源的访问权限。

> 在访问文件前，用户需要先对用于访问文件的应用具备相应权限。
