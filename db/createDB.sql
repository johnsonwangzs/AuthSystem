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

-- 创建组信息表
CREATE TABLE group_info(
	group_id VARCHAR(50) PRIMARY KEY,
	group_name VARCHAR(50) NOT NULL,
	group_description VARCHAR(200)
);

-- 创建角色信息表
CREATE TABLE role_info(
	role_id VARCHAR(50) PRIMARY KEY,
	role_name VARCHAR(50) NOT NULL,
	role_level VARCHAR(50) NOT NULL,
	role_description VARCHAR(200)
);

-- 创建应用信息表
CREATE TABLE app_info(
	app_id VARCHAR(50) PRIMARY KEY,
	app_name VARCHAR(50) NOT NULL,
	app_description VARCHAR(200)
);

-- 创建用户权限表
CREATE TABLE user_authority(
	user_id VARCHAR(50) PRIMARY KEY,
	group_id VARCHAR(50),
	role_id VARCHAR(50)
);

-- 创建应用-组许可规则
CREATE TABLE app_group_rule(
	app_group_rule_id INTEGER PRIMARY KEY,
	app_id VARCHAR(50) NOT NULL,
	group_id VARCHAR(50)
);

-- 创建应用-角色许可规则
CREATE TABLE app_role_rule(
	app_role_rule_id INTEGER PRIMARY KEY,
	app_id VARCHAR(50) NOT NULL,
	role_id VARCHAR(50) NOT NULL
);

-- 创建应用-用户许可规则
CREATE TABLE app_user_rule(
	app_user_rule_id INTEGER PRIMARY KEY,
	app_id VARCHAR(50) NOT NULL,
	user_id VARCHAR(50) NOT NULL
);

-- 创建文件-组许可规则
CREATE TABLE file_group_rule(
	app_group_rule_id INTEGER PRIMARY KEY,
	file_id VARCHAR(50) NOT NULL,
	group_id VARCHAR(50),
	rule VARCHAR(50) NOT NULL
);

-- 创建文件-角色许可规则
CREATE TABLE file_role_rule(
	app_role_rule_id INTEGER PRIMARY KEY,
	file_id VARCHAR(50) NOT NULL,
	role_id VARCHAR(50) NOT NULL,
	rule VARCHAR(50) NOT NULL
);

-- 创建文件-用户许可规则
CREATE TABLE file_user_rule(
	app_user_rule_id INTEGER PRIMARY KEY,
	file_id VARCHAR(50) NOT NULL,
	user_id VARCHAR(50) NOT NULL,
	rule VARCHAR(50) NOT NULL
);


-- 插入数据
INSERT INTO AuthProject.login(user_id, password) values ('000000', 'admin');
INSERT INTO AuthProject.login(user_id, password) values ('010001', 'alice');
INSERT INTO AuthProject.login(user_id, password) values ('010002', 'bob');
INSERT INTO AuthProject.login(user_id, password) values ('010003', 'charlie');
INSERT INTO AuthProject.login(user_id, password) values ('020001', 'dave');
INSERT INTO AuthProject.login(user_id, password) values ('020097', 'eve');
INSERT INTO AuthProject.login(user_id, password) values ('030001', 'fernando');
INSERT INTO AuthProject.login(user_id, password) values ('030028', 'giao');


INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('000000', 'Administer', 'Admin', '15810716511', 'wangzs@buaa.edu.cn', 'The administer of this AuthProject.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('010001', 'Alice', 'meAlice', '', '', 'Because I am the CEO, I do not like Bob.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('010002', 'Bob', 'Boby', '', '', 'I like Alice. Plus, I am the CTO.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('010003', 'Charlie', '', '', '', 'I am the great CFO.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('020001', 'Dave', '', '', '', 'I am the financial director.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('020097', 'Eve', '', '11012010086', '', 'I am a staff working in financial department.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('030001', 'Fernando', '', '', 'fernando@ggmail.com', 'I am the Director of Human Resources Department.');
INSERT INTO AuthProject.user_info(user_id, name, nickname, phone, email, description) values ('030028', 'Giao', 'GiaoTheGanker', '', '', 'I am a senior staff working in Human Resources Department.');


INSERT INTO AuthProject.group_info(group_id, group_name, group_description) values ('00', 'Superior', 'The super administrator.');
INSERT INTO AuthProject.group_info(group_id, group_name, group_description) values ('01', 'Management', 'Enterprise management.');
INSERT INTO AuthProject.group_info(group_id, group_name, group_description) values ('02', 'Financial Department', 'The financial department of the enterprise.');
INSERT INTO AuthProject.group_info(group_id, group_name, group_description) values ('03', 'Human Resources Department', 'The human resources department of the enterprise.');


INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('000', 'Super Administrator', '10', 'The ONLY-ONE.');
INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('001', 'Capital Officer', '9', 'CEO, CFO, CTO, etc.');
INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('002', 'President', '8', 'Corporate President.');
INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('003', 'Director', '7', 'Department Director.');
INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('006', 'Senior Staff', '4', 'Senior Staff.');
INSERT INTO AuthProject.role_info(role_id, role_name, role_level, role_description) values ('007', 'Staff', '3', 'Staff.');


INSERT INTO AuthProject.app_info(app_id, app_name, app_description) values ('0001', 'SearchUser', 'Search users in database.');
INSERT INTO AuthProject.app_info(app_id, app_name, app_description) values ('0002', 'FileArchive', 'Archive of files.');
INSERT INTO AuthProject.app_info(app_id, app_name, app_description) values ('0003', 'ModifyInfo', 'Modify others personal information.');
INSERT INTO AuthProject.app_info(app_id, app_name, app_description) values ('0004', 'ModifySpecialAuthority', 'Modify special authority of users.');


INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('000000', '00', '000');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('010001', '01', '001');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('010002', '01', '001');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('010003', '01', '001');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('020001', '02', '003');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('020097', '02', '007');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('030001', '03', '003');
INSERT INTO AuthProject.user_authority(user_id, group_id, role_id) values ('030028', '03', '006');


INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (1, '0001', '00');
INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (2, '0001', '01');
INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (3, '0002', '00');
INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (4, '0002', '01');
INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (5, '0003', '00');
INSERT INTO AuthProject.app_group_rule(app_group_rule_id, app_id, group_id) values (6, '0004', '00');


INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (1, '0001', '000');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (2, '0001', '001');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (3, '0001', '002');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (4, '0001', '003');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (5, '0002', '000');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (6, '0002', '001');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (7, '0002', '002');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (8, '0002', '003');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (9, '0003', '000');
INSERT INTO AuthProject.app_role_rule(app_role_rule_id, app_id, role_id) values (10, '0004', '000');


