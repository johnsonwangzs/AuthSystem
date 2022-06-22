# AuthSystem
A authentication and authority management system based on Flask.
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
