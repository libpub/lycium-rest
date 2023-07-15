#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from wtforms import Form
from hawthorn.modelutils import ModelBase, get_model_class_name
from .accesscontrol.authorizedsession import SESSION_UID_KEY
from .restdescriptor import RESTfulAPIWraper, Relations, Operations, set_restful_api_by_model
from .register import register_model_general_api_handlers, register_model_page_descriptor_api_handler

__all__ = ['restful_api', 'SESSION_UID_KEY', 'RESTfulAPIWraper', 'Relations', 'Operations']

LOG = logging.getLogger('hawthorn.restfulwrapper')

__restful_api_wrappers: dict[str, RESTfulAPIWraper] = {}
__page_descriptor_model_wrappers: dict[str, RESTfulAPIWraper] = {}
__restful_api_registered = False

def restful_api(endpoint: str = '', title='', form: Form = None, **kwargs):
    """
    wrapper model as RESTful API endpoint

    usage:  @restful_api(endpoint='/api/model1', title='Models', form=Model1Form, auto_association='parent_id')
            class ModelName():
                def __init__(self):
                    pass
    :param endpoint: RESTful API uri prefix path to be registered to http server
    
    :param title: title name of this model to be displayed in frontend page
    
    :param form: wtforms.Form to validate for add and update operations
    
    :param auto_association: specify attribute name for auto self association relations column, if the model
        has more self association relations, use list object.
    """
    def decorator(cls: ModelBase):
        uri = endpoint
        model_name = get_model_class_name(cls)
        if not uri:
            uri = '/api/' + model_name.lower() + 's'
            LOG.info('treat %s as RESTful URI:%s', model_name, uri)
            
        auto_association = kwargs.pop('auto_association', None)
        custom_relations: Relations | list[Relations] = kwargs.pop('relations', None)
        if uri and uri not in __restful_api_wrappers:
            if custom_relations:
                if isinstance(custom_relations, list):
                    [cr.set_src_model(cls) for cr in custom_relations]
                else:
                    custom_relations.set_src_model(cls)
            w = RESTfulAPIWraper(uri, cls, title=title, form=form, auto_association = auto_association, custom_relations=custom_relations)
            __restful_api_wrappers[uri] = w
            route_pieces = uri.split('/')
            page_name = route_pieces[len(route_pieces)-1]
            __page_descriptor_model_wrappers[page_name] = w
            set_restful_api_by_model(model_name, uri)
        else:
            raise ValueError("Duplicate registering model RESTful URI '%s'" % (uri))
        
        return cls
    return decorator

def get_all_restful_api_wrappers():
    return __restful_api_wrappers

def get_page_descriptor_model(pathname: str) -> RESTfulAPIWraper:
    if pathname in __page_descriptor_model_wrappers:
        return __page_descriptor_model_wrappers[pathname]
    return None

def register_restful_apis():
    global __restful_api_registered
    if not __restful_api_wrappers or __restful_api_registered:
        return
    for endpoint, w in __restful_api_wrappers.items():
        if endpoint and w.cls:
            # LOG.info('registing RESTful endpoint %s', endpoint)
            register_model_general_api_handlers(w.cls, endpoint, form=w.form, auto_association=w._auto_association, custom_relations=w._custom_relations)
    register_model_page_descriptor_api_handler(get_page_descriptor_model)
    __restful_api_registered = True
