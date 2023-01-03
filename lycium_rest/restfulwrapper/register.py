#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import tornado.web
import tornado.httputil
from wtforms import Form
from hawthorn.asynchttphandler import GeneralTornadoHandler, routes
from hawthorn.modelutils import ModelBase, meta_data, get_model_class_name, model_columns
from .accesscontrol.authorizedsession import authorized_session_access_control
from .restdescriptor import Relations
from .utils import find_model_class_by_cls_name, find_model_class_by_table_name
from .modelapihandlers import ModelRESTfulHandler
from .modelrelationhandlers import ModelRelationsRESTfulHandler
from .pagedescriptorhandlers import ModelPageDescriptorsApiHandler

LOG = logging.getLogger('lycium.restfulwrapper.register')

def register_model_general_api_handlers(model: ModelBase, endpoint: str = '', form: Form = None, web_app: tornado.web.Application=None, **options):
    ac = options.pop('ac', [])
    auto_association = options.pop('auto_association', None)
    custom_relations: Relations | list[Relations] = options.pop('custom_relations', None)
    if not ac:
        ac = [authorized_session_access_control]
    endpoint = prepare_model_endpoint(model, endpoint)
    relationship_attrs, auto_association_attrs = lookup_model_relationship_attrs(model)
    if not auto_association:
        auto_association = auto_association_attrs

    uri = endpoint+r'(?:/(?P<id>\w+))?'
    local_routes = [
        (uri, ModelRESTfulHandler, dict(model=model, form=form, ac=ac, auto_association=auto_association))
    ]
    LOG.info('registing RESTful endpoint %s', uri)
    registered_middle_relations = {}
    for attr_key, relation_params in relationship_attrs.items():
        uri = endpoint + r'/(?P<instanceID>\w+)/' + attr_key
        local_routes.append((uri, ModelRelationsRESTfulHandler, relation_params))
        LOG.info('registing relations RESTful endpoint %s', uri)
        registered_middle_relations[get_model_class_name(relation_params['middle_model'])] = True
    if custom_relations:
        crs: list[Relations] = custom_relations if isinstance(custom_relations, list) else [custom_relations]
        for cr in crs:
            cr.prepare()
            if get_model_class_name(cr.middle_model) not in registered_middle_relations:
                uri = endpoint + r'/(?P<instanceID>\w+)/' + get_model_class_name(cr.dst_model).lower() + 's'
                local_routes.append((uri, ModelRelationsRESTfulHandler, dict(middle_model=cr.middle_model, src_field=cr.src_field, dst_field=cr.dst_field, src_model=model, dst_model=cr.dst_model)))
                LOG.info('registing relations RESTful endpoint %s', uri)

    if web_app:
        [web_app.add_handlers(route[0], route) for route in local_routes]
    else:
        routes.routes.extend(local_routes)

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

def prepare_model_endpoint(model: ModelBase, endpoint: str):
    if not endpoint:
        endpoint = '/' + str(get_model_class_name(model)).lower() + 's'
    if endpoint.endswith('/'):
        endpoint.rstrip('/')
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
    return endpoint

def lookup_model_relationship_attrs(model: ModelBase):
    relationship_attrs = {}
    auto_association_attrs = []
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
                        relationship_attrs[attr.key] = dict(middle_model=middle_model, src_field=src_field, dst_field=dst_field, src_model=src_model, dst_model=dst_model)
            elif attr.expression.foreign_keys:
                for fk in attr.expression.foreign_keys:
                    if fk.constraint.parent.fullname == model.__tablename__:
                        auto_association_attrs.append(attr.key)
    return relationship_attrs, auto_association_attrs
