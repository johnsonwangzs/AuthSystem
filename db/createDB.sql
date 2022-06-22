-- 新建库
CREATE DATABASE AuthProject;

-- 切换库
USE AuthProject;


-- 创建用户登录表
CREATE TABLE login(
	user_id VARCHAR(50) PRIMARY KEY,
	password VARCHAR(50) NOT NULL
);

-- 创建用户基本信息表
CREATE TABLE user_info(
	user_id VARCHAR(50) PRIMARY KEY,
	name VARCHAR(50) NOT NULL,
	nickname VARCHAR(50),
	phone VARCHAR(50),
	email VARCHAR(50),
	description VARCHAR(200)
);


-- 插入数据
INSERT INTO AuthProject.login(user_id, password) values ('000000', 'admin');
INSERT INTO AuthProject.login(user_id, password) values ('010001', 'alice');
INSERT INTO AuthProject.login(user_id, password) values ('030001', 'bob');
INSERT INTO AuthProject.login(user_id, password) values ('070001', 'charlie');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('000000', 'Administer', 'Admin', '15810716511', 'wangzs@buaa.edu.cn', 'The administer of this AuthProject.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('010001', 'Alice', 'meAlice', '', '', 'Because I am the CEO, I do not like Bob.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('030001', 'Bob', 'Boby', '', '', 'I like Alice. Plus, I am the CTO.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('070001', 'Charlie', '', '', '', 'I am the great CFO.');
