#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys
import time
import logging
import i18n
import http
import json
import hawthorn
import tornado.gen
import tornado.web
import tornado.httputil
from tornado.ioloop import IOLoop
from sqlalchemy import Column, Integer, BigInteger, SmallInteger, String, ForeignKey
from sqlalchemy.orm import relationship
from wtforms import Form
from wtforms import StringField, IntegerField, BooleanField, HiddenField
from wtforms.validators import DataRequired, NumberRange, Length, Regexp, AnyOf, Email
from hawthorn.dbproxy import DbProxy
from hawthorn.webapplication import WebApplication
from hawthorn.asynchttphandler import GeneralTornadoHandler, async_route, request_body_as_json, set_default_headers
from hawthorn.asyncrequest import async_http_request, async_post_json
from hawthorn.modelutils import ModelBase, meta_data
from hawthorn.modelutils.behaviors import ModifyingBehevior
import unittest

import lycium_rest
from lycium_rest.utilities import get_current_timestamp, verify_password, generate_password
from lycium_rest.restfulwrapper import register_restful_apis, restful_api, SESSION_UID_KEY, Relations, Operations
from lycium_rest.migrationutils import set_appname, set_migrates, do_migrations
from lycium_rest.valueobjects.resultcodes import RESULT_CODE
from lycium_rest.valueobjects.responseobject import GeneralResponseObject
from lycium_rest.formvalidation.formutils import validate_form
from lycium_rest.formvalidation.validators import DateTimeValidator

class CONF:
    rdbms = {
        'default': {
            'connector': "sqlite",
            'driver': "sqlite",
            'host': "./unittest.db",
            'port': 0,
            'user': "changeit",
            'pwd': "changeit",
            'db': "unittest",
        }
    }
    server = {
        'host': '127.0.0.1',
        'port': 32767
    }
    static_uri = '/static'
    static_folder = 'views/static'
    template_folder = 'views/templates'

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

class UserSigninForm(Form):
    """
    User signin form for validating
    """

    username = StringField(label='用户名', id='account',
        validators=[
            DataRequired('请输入用户名'),
            Length(max=64, message='用户名过长'),
        ])
    password = StringField(label='用户密码', id='password_hash',
        validators=[
            DataRequired('请输入用户密码'),
            Length(max=80, message='用户密码内容过长'),
            Length(min=5, message='用户密码内容过短'),
            # Regexp(r'^[A-Za-z0-9_=\-+]+$', message='用户密码不符合要求')
        ])
    autoLogin = BooleanField(label='自动登录')
    type = StringField(label='登录类型')

class UserForm(Form):
    """
    User form for validating
    """
    name = StringField(label='用户名', 
        id='account',
        validators=[
            DataRequired('请输入用户名'),
            Length(max=64, message='用户名过长'),
        ])
    email = StringField(label='邮箱', 
        validators=[
            DataRequired('请输入邮箱'),
            # Email(message='邮箱格式不正确'),
            Length(max=255, message='邮箱过长'),
        ])
    telephone = StringField(label='手机号码', 
        validators=[
            DataRequired('请输入手机号码'),
            Regexp(r'^1\d{10}$', message='请输入正确的手机号码')
        ])
    avatar = StringField(label='头像', 
        validators=[
            DataRequired('请上传用户头像'),
            Length(max=255, message='头像地址过长'),
        ])
    password = StringField(label='用户密码', id='password_hash',
        validators=[
            DataRequired('请输入用户密码'),
            Length(max=80, message='用户密码内容过长'),
            Length(min=6, message='用户密码内容过短'),
            Regexp(r'^[A-Za-z0-9_=\-+]+$', message='用户密码不符合要求')
        ])
    status = IntegerField(label='状态',
        validators=[
            AnyOf({0: '正常', 1: '禁用'}, message='请选择正确的用户状态')
        ])
    expiresAt = StringField(label='过期时间', id='expires_at',
        validators=[
            DateTimeValidator()
        ])
    passwordExpiresAt = StringField(label='密码过期时间', id='password_expires_at',
        validators=[
            DateTimeValidator()
        ])
    unlocksAt = StringField(label='账户解锁时间', id='unlocks_at',
        validators=[
            DateTimeValidator()
        ])

class RoleForm(Form):
    """
    Role form for validating
    """

    name = StringField(label='角色名', 
        id='name',
        validators=[
            DataRequired('请输入角色名'),
            Length(max=64, message='角色名过长'),
        ])
    avatar = StringField(label='头像', 
        validators=[
            # DataRequired('请上传头像'),
            Length(max=255, message='头像地址过长'),
        ])
    status = IntegerField(label='状态',
        validators=[
            AnyOf({0: '正常', 1: '禁用'}, message='请选择正确的角色状态')
        ])
    
class _UserTable(ModelBase):
    __tablename__ = 'au_user'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    account = Column('account', String(64), index=True, unique=True)
    email = Column('email', String(128), index=True)
    telephone = Column('telephone', String(32), index=True)
    avatar = Column('avatar', String(256), default='')
    password_hash = Column('passwd_hash', String(128))
    status = Column('status', SmallInteger, index=True, default=0)
    expires_at = Column('expires_at', BigInteger, comment='User account expirement timestamp', default=0)
    password_expires_at = Column('passwd_expires', BigInteger, comment='User password expirement timestamp', default=0)
    unlocks_at = Column('unlocks_at', BigInteger, comment='User account unlock timestamp if frozen', default=0)
    last_signin_at = Column('last_signin_at', BigInteger, default=0)
    signin_count = Column('signin_count', Integer, default=0)

# test specify exact endpoint
@restful_api(endpoint='/api/users', title='Users', form=UserForm)
class User(_UserTable, ModifyingBehevior):
    
    roles = relationship('Role', secondary='au_user_assignment')
    
    __hidden_response_fields__ = ['password_hash']
    operations = Operations([Operations.VIEW, {'action': 'relation', 'title': i18n.t('basic.role'), 'searchURL': '/api/roles', 'saveURL': '/api/users/:id/roles'}, Operations.EDIT, Operations.DELETE])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def verify_password(self, password: str):
        return verify_password(password, self.password_hash)
    
    def set_password_hash(self, password: str):
        self.password_hash = generate_password(password)

    def simple_user_dict(self):
        return {
            'uid': self.id,
            'name': self.account,
            'email': self.email,
            'status': self.status,
        }

class _RoleTable(ModelBase):
    __tablename__ = 'au_role'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String(64), index=True, unique=True)
    avatar = Column('avatar', String(256), default='')
    status = Column('status', SmallInteger, index=True, default=0)

# test auto generate endpoint
@restful_api(endpoint='/api/roles', title='Roles', form=RoleForm, relations=[Relations('RoleAssignment', 'role_id', 'permission_id', 'Permission')])
class Role(_RoleTable, ModifyingBehevior):
    # permissions = relationship('Permission', secondary='au_role_assignment')
    operations = Operations([{'action': 'relation', 'title': i18n.t('basic.permission'), 'searchURL': '/api/permissions/fetchTree', 'saveURL': '/api/roles/:id/permissions'}, Operations.EDIT, Operations.DELETE])
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _UserAssignmentTable(ModelBase):
    __tablename__ = 'au_user_assignment'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    user_id = Column('user_id', ForeignKey(_UserTable.__tablename__ + '.' + User.id.name), index=True)
    role_id = Column('role_id', ForeignKey(_RoleTable.__tablename__ + '.' + Role.id.name), index=True)

class UserAssignment(_UserAssignmentTable, ModifyingBehevior):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _PermissionTable(ModelBase):
    __tablename__ = 'au_permission'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String(64), index=True)
    path = Column('path', String(256), index=True, unique=True)
    parent_id = Column('parent_id', Integer, index=True, default=0)
    icon = Column('icon', String(256), default='')
    status = Column('status', SmallInteger, index=True, default=0)
    displayorder = Column('displayorder', SmallInteger, index=True, default=0)

@restful_api(endpoint='/api/permissions', title='Permissions', form=None, auto_association='parent_id')
class Permission(_PermissionTable, ModifyingBehevior):
    """
    权限信息
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _RoleAssignmentTable(ModelBase):
    __tablename__ = 'au_role_assignment'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    role_id = Column('role_id', ForeignKey(_RoleTable.__tablename__ + '.' + Role.id.name), index=True)
    permission_id = Column('permission_id', ForeignKey(_PermissionTable.__tablename__ + '.' + Permission.id.name), index=True)

class RoleAssignment(_RoleAssignmentTable, ModifyingBehevior):
    """
    角色与权限关联表
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _OrganizationTable(ModelBase):
    __tablename__ = 'sys_organization'
    
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    code = Column('code', String(64), index=True)
    name = Column('name', String(64), index=True)
    parent_id = Column('parent_id', ForeignKey('sys_organization.id'), index=True, default=0)

@restful_api(endpoint='/api/organizations', title='Organazations', form=None)
class Organization(_OrganizationTable, ModifyingBehevior):
    """
    组织机构表
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

APP_NAME = 'lycium_rest.unittest'
LOG = logging.getLogger(APP_NAME)

async def migrate_v000100_v000101():
    print('migrate_v000100_v000101')
    u = User()
    u.set_session_uid(APP_NAME)
    u.account = 'admin'
    u.email = f'admin@{APP_NAME}.local'
    u.password_hash = generate_password('admin')
    u.status = 0
    u.expires_at = 0
    u.unlocks_at = 0
    u.password_expires_at = int(time.time()*1000)
    await DbProxy().insert_item(u, auto_flush=True)

    # create admin role
    r = Role()
    r.set_session_uid(APP_NAME)
    r.name = 'System Administrator'
    r.status = 0
    r = await DbProxy().insert_item(r, auto_flush=True)
    
    # create permissions
    permissions = [
        {'name': '首页', 'path': '/home', 'icon': 'home', 'displayorder': 1},
        {'name': '系统管理', 'path': '/sysadmin', 'icon': 'setting', 'displayorder': 9, 'children': [
            {'name': '用户管理', 'path': '/sysadmin/users', 'icon': 'user'},
            {'name': '角色管理', 'path': '/sysadmin/roles', 'icon': 'team'},
            {'name': '权限管理', 'path': '/sysadmin/permissions', 'icon': 'lock'},
        ]},
    ]
    permission_ids = []
    for e in permissions:
        await save_tree_model(Permission, 'id', 'parent_id', e, permission_ids, 'displayorder')
        
    # assign role permissions
    for id in permission_ids:
        ra = RoleAssignment()
        ra.set_session_uid(APP_NAME)
        ra.permission_id = id
        ra.role_id = r.id
        await DbProxy().insert_item(ra, auto_flush=True)
        
    # asssign user role
    ua = UserAssignment()
    ua.set_session_uid(APP_NAME)
    ua.user_id = u.id
    ua.role_id = r.id
    await DbProxy().insert_item(ua, auto_flush=True)
    
    # organizations
    organizations = [
        {'code': '1001', 'name': '集团', 'children': [
            {'code': '100101', 'name': '综合部'},
            {'code': '100102', 'name': '研发部', 'children': [
                {'code': '10010201', 'name': '创新事业部'},
                {'code': '10010202', 'name': 'AI事业部'},
                {'code': '10010202', 'name': '大数据事业部'}
            ]},
            {'code': '100103', 'name': '销售部', 'children': [
                {'code': '10010301', 'name': '销售一部'},
                {'code': '10010302', 'name': '销售二部'}
            ]}
        ]}
    ]
    organization_ids = []
    for e in organizations:
        await save_tree_model(Organization, 'id', 'parent_id', e, organization_ids, None)

async def save_tree_model(model: ModelBase, pk: str, parent_key: str, e: dict, saved_ids: list, displayorder_key: str = None, parent_id: int = 0, parent_displayorder: int = 0):
    m = model()
    if hasattr(m, 'set_session_uid'):
        m.set_session_uid(APP_NAME)
    for k, v in e.items():
        if hasattr(m, k):
            setattr(m, k, v)
    setattr(m, parent_key, parent_id)
    if displayorder_key:
        if displayorder_key in e:
            setattr(m, displayorder_key, e[displayorder_key])
            parent_displayorder = e[displayorder_key]
        else:
            setattr(m, displayorder_key, parent_displayorder)
    m = await DbProxy().insert_item(m, auto_flush=True)
    saved_ids.append(getattr(m, pk))
    if 'children' in e:
        for e1 in e['children']:
            await save_tree_model(model, pk, parent_key, e1, saved_ids, displayorder_key, getattr(m, pk), parent_displayorder)

set_appname(APP_NAME)
set_migrates([migrate_v000100_v000101])

async def do_user_login(signin_form: UserSigninForm):
    locale_params = {}
    u: User = await DbProxy().find_item(User, {User.account==signin_form.username.data})
    if not u:
        LOG.warning('user [%s] login failed while user does not extsts', signin_form.username.data)
        return GeneralResponseObject(code=RESULT_CODE.DATA_DOES_NOT_EXISTS, message=i18n.t('basic.user_not_exists', **locale_params)), None

    if not u.verify_password(signin_form.password.data):
        LOG.warning('user [%s] login failed while given password not correct', signin_form.username.data)
        return GeneralResponseObject(code=RESULT_CODE.PASSWORD_NOT_CORRECT, message=i18n.t('basic.password_not_correct', **locale_params)), None

    now = get_current_timestamp()
    if u.expires_at > 0 and u.expires_at < now:
        LOG.warning('user [%s] login failed while user account were expired', signin_form.username.data)
        return GeneralResponseObject(code=RESULT_CODE.ACCOUNT_EXPIRED, message=i18n.t('basic.account_expired', **locale_params)), None
    if u.unlocks_at > now:
        LOG.warning('user [%s] login failed while user account were frozen', signin_form.username.data)
        return GeneralResponseObject(code=RESULT_CODE.ACCOUNT_WERE_FROZEN, message=i18n.t('basic.account_were_frozen', **locale_params)), None

    u.set_session_uid(u.id)
    u.last_signin_at = now
    if u.signin_count:
        u.signin_count = u.signin_count + 1
    else:
        u.signin_count = 1
    await DbProxy().update_item(u)
    return GeneralResponseObject(code=RESULT_CODE.OK, message=i18n.t('basic.success', **locale_params)), u

@async_route('/api/user/signin', methods=['POST'])
@tornado.gen.coroutine
def handler_user_signin(handler: GeneralTornadoHandler, request: tornado.httputil.HTTPServerRequest):
    LOG.info('handling user signin request')
    inputs = request_body_as_json(request)
    form_item = UserSigninForm(formdata=None, data=inputs, meta={ 'csrf': False })
    result = validate_form(form_item)
    if not result.is_success():
        return result.encode_json()

    result, u = yield do_user_login(form_item)
    if not result.is_success():
        return result.encode_json()

    handler.session[SESSION_UID_KEY] = u.id

    result.data = u.simple_user_dict()
    return result.encode_json()

register_restful_apis()
web_app = WebApplication(static_path=os.path.abspath(CONF.static_folder),
                         static_url_prefix=CONF.static_uri,
                         template_path=os.path.abspath(CONF.template_folder),
                         cookie_secret='0123456789')

class TestModelRESTful(unittest.IsolatedAsyncioTestCase):
    
    async def asyncSetUp(self):
        lycium_rest.init_i18n('zh_CN')
        print("Application loading...")
        if CONF.rdbms:
            if os.path.exists(CONF.rdbms['default'].get('host')):
                os.remove(CONF.rdbms['default'].get('host'))
            DbProxy().setup_rdbms(CONF.rdbms)
        print("Application initializing...")
        await do_migrations()
        print("Application running...")
        set_default_headers({"Access-Control-ALLow-Origin": "*", "Access-Control-ALLoW-Headers": "*"})
        web_app.listen(port=CONF.server.get('port'), address=CONF.server.get('host'))
        self.addAsyncCleanup(self.do_cleanup)
        
    async def test_model_restful(self):
        # 1. login
        params = {
            'username': 'admin',
            'password': 'admin'
        }
        endpoint_domain = CONF.server['host'] + ':' + str(CONF.server['port'])
        resp = await async_http_request('POST', f"http://{endpoint_domain}/api/user/signin", json=params)
        print("headers:", resp.headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        # print('login result:', str(resp.body.decode()))
        cookie = resp.headers.get('Set-Cookie')
        headers = {
            'Cookie': cookie
        }

        # test RESTful GET by id
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users/1", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get user element result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        # test RESTful GET list
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get users list result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        # test RESTful new record
        expire_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()+86400))
        post_data = {
            'name': 'guest01',
            'email': f'guest01@{APP_NAME}',
            'telephone': '15012345678',
            'avatar': 'https://gw.alipayobjects.com/zos/antfincdn/XAosXuNZyF/BiazfanxmamNRoxxVxka.png',
            'password': 'guest01',
            'status': 0,
            'expiresAt': expire_date,
            'passwordExpiresAt': expire_date,
            'unlocksAt': expire_date,
        }
        resp = await async_http_request('POST', f"http://{endpoint_domain}/api/users", params={}, json=post_data, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('new user result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        # test RESTful GET findOne by condition
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users/findOne", params={'account': 'guest01'}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get user element result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        test_uid = result_data.get('data', {}).get('id', 0)
        self.assertGreater(test_uid, 0)
        
        resp = await async_http_request('PUT', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, json=post_data, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('update full fields user result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        resp = await async_http_request('PATCH', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, json=post_data, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('update patch fields user result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        roles = [
            {'name': 'role1', 'status': 0}, {'name': 'role2', 'status': 0}
        ]
        resp = await async_http_request('POST', f"http://{endpoint_domain}/api/roles", params={}, json=roles, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('new roles result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/roles", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get roles list result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        role_ids = []
        for role_data in json.loads(resp.body).get('data', []):
            if role_data['name'].startswith('role'):
                role_ids.append(role_data['id'])
        
        resp = await async_http_request('POST', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, json={'role_id': role_ids}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('new user-role mapper result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        resp = await async_http_request('PATCH', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, json={'role_id': role_ids[0]}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('update user-role mapper result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        resp = await async_http_request('DELETE', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('delete user-role mapper result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        resp = await async_http_request('DELETE', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('delete user result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        # test tree list data
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/permissions/fetchTree", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get permissions list result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/organizations/fetchTree", params={}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get organizations list result:', str(resp.body.decode()))
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)
        
        # do get descriptor tests
        resp = await async_http_request('GET', f"http://{endpoint_domain}/api/pages/descriptors", params={'pathname': '/pages/users'}, headers=headers)
        self.assertEqual(resp.code, http.HTTPStatus.OK)
        print('get page descriptor result:', resp.body.decode())
        result_data = json.loads(resp.body)
        self.assertEqual(result_data.get('code', -1), 0)

        print("stopping testing ioloop...")
        
    async def do_cleanup(self):
        print("clean testing db ...")
        os.remove(CONF.rdbms['default'].get('host'))
        print("testing finished.")
        
if __name__ == '__main__':
    unittest.main()
