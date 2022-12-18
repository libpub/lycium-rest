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
from hawthorn.asynchttphandler import GeneralTornadoHandler, async_route, request_body_as_json
from hawthorn.asyncrequest import async_http_request, async_post_json
from hawthorn.modelutils import ModelBase, meta_data
from hawthorn.modelutils.behaviors import ModifyingBehevior

import lycium_rest
from lycium_rest.utilities import get_current_timestamp, verify_password, generate_password
from lycium_rest.restfulwrapper import register_restful_apis, restful_api, SESSION_UID_KEY
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
    __tablename__ = 'sys_user'

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
    
    roles = relationship('Role', secondary='sys_user_role')
    
    __hidden_response_fields__ = ['password_hash']
    
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
    __tablename__ = 'sys_role'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String(64), index=True, unique=True)
    avatar = Column('avatar', String(256), default='')
    status = Column('status', SmallInteger, index=True, default=0)

# test auto generate endpoint
@restful_api(endpoint='/api/roles', title='Roles', form=RoleForm)
class Role(_RoleTable, ModifyingBehevior):
    # users = relationship('User', secondary='sys_user_role')
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _UserRoleTable(ModelBase):
    __tablename__ = 'sys_user_role'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    user_id = Column('user_id', ForeignKey(_UserTable.__tablename__ + '.' + User.id.name), index=True)
    role_id = Column('role_id', ForeignKey(_RoleTable.__tablename__ + '.' + Role.id.name), index=True)
    # user_id = Column('user_id', Integer, unique=True)
    # role_id = Column('role_id', Integer, unique=True)

# @restful_api('/api/userrole', relations=Relations('user_id', 'role_id', User, Role))
class UserRoleMapper(_UserRoleTable, ModifyingBehevior):
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

async def do_tests():
    # 1. login
    params = {
        'username': 'admin',
        'password': 'admin'
    }
    endpoint_domain = CONF.server['host'] + ':' + str(CONF.server['port'])
    resp = await async_http_request('POST', f"http://{endpoint_domain}/api/user/signin", json=params)
    assert resp.code == http.HTTPStatus.OK
    print('login result:', str(resp.body.decode()))
    cookie = resp.headers.get('Set-Cookie')
    headers = {
        'Cookie': cookie
    }

    # test RESTful GET by id
    resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users/1", params={}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('get user element result:', str(resp.body.decode()))

    # test RESTful GET list
    resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users", params={}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('get users list result:', str(resp.body.decode()))
    
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
    assert resp.code == http.HTTPStatus.OK
    print('new user result:', str(resp.body.decode()))
    
    # test RESTful GET findOne by condition
    resp = await async_http_request('GET', f"http://{endpoint_domain}/api/users/findOne", params={'account': 'guest01'}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('get user element result:', str(resp.body.decode()))
    
    test_uid = json.loads(resp.body).get('data', {}).get('id', 0)
    
    resp = await async_http_request('PUT', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, json=post_data, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('update full fields user result:', str(resp.body.decode()))
    
    resp = await async_http_request('PATCH', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, json=post_data, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('update patch fields user result:', str(resp.body.decode()))

    roles = [
        {'name': 'role1', 'status': 0}, {'name': 'role2', 'status': 0}
    ]
    resp = await async_http_request('POST', f"http://{endpoint_domain}/api/roles", params={}, json=roles, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('new roles result:', str(resp.body.decode()))
    
    resp = await async_http_request('GET', f"http://{endpoint_domain}/api/roles", params={}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('get roles list result:', str(resp.body.decode()))
    
    role_ids = []
    for role_data in json.loads(resp.body).get('data', []):
        if role_data['name'].startswith('role'):
            role_ids.append(role_data['id'])
    
    resp = await async_http_request('POST', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, json={'role_id': role_ids}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('new user-role mapper result:', str(resp.body.decode()))

    resp = await async_http_request('PATCH', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, json={'role_id': role_ids[0]}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('update user-role mapper result:', str(resp.body.decode()))

    resp = await async_http_request('DELETE', f"http://{endpoint_domain}/api/users/{test_uid}/roles", params={}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('delete user-role mapper result:', str(resp.body.decode()))

    resp = await async_http_request('DELETE', f"http://{endpoint_domain}/api/users/{test_uid}", params={}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    print('delete user result:', str(resp.body.decode()))
    
    # do get descriptor tests
    resp = await async_http_request('GET', f"http://{endpoint_domain}/api/pages/descriptors", params={'pathname': '/pages/users'}, headers=headers)
    assert resp.code == http.HTTPStatus.OK
    descriptor_result = json.loads(resp.body.decode())
    print('get page descriptor result:', descriptor_result)

    print("stopping testing ioloop...")
    IOLoop.instance().stop()
    pass

def test_model_restful():
    lycium_rest.init_i18n('zh_CN')
    # lycium_rest.init_i18n_locales_path()
    print("Application loading...")
    if CONF.rdbms:
        if os.path.exists(CONF.rdbms['default'].get('host')):
            os.remove(CONF.rdbms['default'].get('host'))
        DbProxy().setup_rdbms(CONF.rdbms)
    print("Application initializing...")
    IOLoop.instance().run_sync(do_migrations)
    print("Application running...")
    web_app.listen(port=CONF.server.get('port'), address=CONF.server.get('host'))
    IOLoop.instance().call_later(0.3, do_tests)
    IOLoop.instance().start()
    # clean testing db
    print("clean testing db ...")
    os.remove(CONF.rdbms['default'].get('host'))
    print("testing finished.")
    os._exit(0)

if __name__ == '__main__':
    test_model_restful()
