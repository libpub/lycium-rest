#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import tornado.web
import tornado.httputil
from wtforms import Form
from hawthorn.asynchttphandler import GeneralTornadoHandler, routes
from hawthorn.modelutils import ModelBase, meta_data, get_model_class_name, model_columns
from .accesscontrol.authorizedsession import authorized_session_access_control
from .modelapihandlers import ModelRESTfulHandler
from .modelrelationhandlers import ModelRelationsRESTfulHandler
from .pagedescriptorhandlers import ModelPageDescriptorsApiHandler

LOG = logging.getLogger('lycium.restfulwrapper.register')

def find_model_class_by_table_name(table_name: str):
    tbl_model: ModelBase = None
    for model in ModelBase.registry.mappers:
        if hasattr(model.class_, '__tablename__') and model.class_.__tablename__ == table_name:
            # print(model.class_.__name__)
            if model.class_.__name__[0] != '_':
                tbl_model = model.class_
                break
    return tbl_model

def find_model_class_by_cls_name(cls_name: str):
    for model in ModelBase.registry.mappers:
        if model.class_.__name__ == cls_name:
            return model.class_
    return None

def register_model_general_api_handlers(model: ModelBase, endpoint: str = '', form: Form = None, web_app: tornado.web.Application=None, **options):
    # handler = ModelApiHandler(model=model, add_form=add_form, edit_form=edit_form)
    ac = options.pop('ac', [])
    if not ac:
        ac = [authorized_session_access_control]
    if not endpoint:
        endpoint = '/' + str(get_model_class_name(model)).lower() + 's'
    if endpoint.endswith('/'):
        endpoint.rstrip('/')
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint

    uri = endpoint+r'(?:/(?P<id>\w+))?'
    local_routes = [
        (uri, ModelRESTfulHandler, dict(model=model, form=form, ac=ac))
    ]
    LOG.info('registing RESTful endpoint %s', uri)
    if hasattr(model, '_sa_class_manager'):
        for attr in model._sa_class_manager.local_attrs.values():
            if attr.prop.strategy_wildcard_key == 'relationship' and attr.prop.secondary:
                tbl = meta_data.tables.get(attr.prop.secondary, None)
                if tbl is not None:
                    middle_model = find_model_class_by_table_name(attr.prop.secondary)
                    src_field = ''
                    dst_field = ''
                    src_model = model
                    dst_model = find_model_class_by_cls_name(attr.prop.argument) if isinstance(attr.prop.argument, str) else attr.prop.argument
                    if not middle_model:
                        continue
                    columns, pk = model_columns(middle_model)
                    for colname in columns:
                        if colname == pk:
                            continue
                        col = getattr(middle_model, colname)
                        if col.expression.foreign_keys:
                            for k in col.expression.foreign_keys:
                                tbl_cols = k.target_fullname.split('.')
                                if len(tbl_cols) < 2:
                                    continue
                                if hasattr(model, '__tablename__') and tbl_cols[0] == model.__tablename__:
                                    src_field = col.key
                                else:
                                    dst_field = col.key
                                break
                    if middle_model is not None and src_field and dst_field and dst_model is not None:
                        uri = endpoint + r'/(?P<instanceID>\w+)/' + attr.key
                        local_routes.append((uri, ModelRelationsRESTfulHandler, dict(middle_model=middle_model, src_field=src_field, dst_field=dst_field, src_model=src_model, dst_model=dst_model)))
                        LOG.info('registing relations RESTful endpoint %s', uri)
    # local_routes.append((uri_prefix+'/get', GeneralTornadoHandler, dict(callback=handler.handler_get, methods=['GET'], ac=ac)))
    # local_routes.append((uri_prefix+'/list', GeneralTornadoHandler, dict(callback=handler.handler_list, methods=['GET'], ac=ac)))
    # local_routes.append((uri_prefix+'/add', GeneralTornadoHandler, dict(callback=handler.handler_add, methods=['POST'], ac=ac)))
    # local_routes.append((uri_prefix+'/edit', GeneralTornadoHandler, dict(callback=handler.handler_edit, methods=['PATCH'], ac=ac)))
    # local_routes.append((uri_prefix+'/delete', GeneralTornadoHandler, dict(callback=handler.handler_delete, methods=['DELETE'], ac=ac)))

    if web_app:
        [web_app.add_handlers(route[0], route) for route in local_routes]
    else:
        routes.routes.extend(local_routes)

# def register_middle_relation_model_api_handlers(model: ModelBase, uri_prefix: str, src_field: str, dst_field: str, src_model: ModelBase, dst_model: ModelBase, web_app: tornado.web.Application=None, **options):
#     handler = ModelRelationsApiHandler(model, src_field, dst_field, src_model, dst_model)
#     ac = options.pop('ac', [])
#     if not ac:
#         ac = [authorized_session_access_control]
#     if not uri_prefix:
#         uri_prefix = '/' + str(get_model_class_name(model)).lower() + 's'
#     if uri_prefix.endswith('/'):
#         uri_prefix.rstrip('/')
#     if not uri_prefix.startswith('/'):
#         uri_prefix = '/' + uri_prefix

#     local_routes = []
#     local_routes.append((uri_prefix+'/list', GeneralTornadoHandler, dict(callback=handler.handler_relation_ids, methods=['GET'], ac=ac)))
#     local_routes.append((uri_prefix+'/add', GeneralTornadoHandler, dict(callback=handler.handler_add, methods=['POST'], ac=ac)))
#     local_routes.append((uri_prefix+'/update', GeneralTornadoHandler, dict(callback=handler.handler_update, methods=['PATCH'], ac=ac)))
#     local_routes.append((uri_prefix+'/delete', GeneralTornadoHandler, dict(callback=handler.handler_delete, methods=['DELETE'], ac=ac)))

#     if web_app:
#         [web_app.add_handlers(route[0], route) for route in local_routes]
#     else:
#         routes.routes.extend(local_routes)

def register_model_page_descriptor_api_handler(get_page_descriptor_model, web_app: tornado.web.Application=None, **options):
    handler = ModelPageDescriptorsApiHandler(get_page_descriptor_model)
    ac = options.pop('ac', [])
    if not ac:
        ac = [authorized_session_access_control]
    local_routes = [
        ('/api/pages/descriptors', GeneralTornadoHandler, dict(callback=handler.handler_get, methods=['GET'], ac=ac))
    ]
    if web_app:
        [web_app.add_handlers(route[0], route) for route in local_routes]
    else:
        routes.routes.extend(local_routes)
