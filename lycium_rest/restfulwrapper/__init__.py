#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from wtforms import Form
from hawthorn.modelutils import ModelBase, get_model_class_name
from .accesscontrol.authorizedsession import SESSION_UID_KEY
from .restdescriptor import RESTfulAPIWraper
from .register import register_model_general_api_handlers, register_model_page_descriptor_api_handler

__all__ = ['restful_api', 'SESSION_UID_KEY']

LOG = logging.getLogger('hawthorn.restfulwrapper')

__restful_api_wrappers: dict[str, RESTfulAPIWraper] = {}
__page_descriptor_model_wrappers: dict[str, RESTfulAPIWraper] = {}
__restful_api_registered = False

def restful_api(endpoint: str = '', title='', form: Form = None, **kwargs):
    """
    wrapper model as RESTful API endpoint

    usage:  @restful_api(endpoint)
            class ModelName():
                def __init__(self):
                    pass
    """
    def decorator(cls: ModelBase):
        uri = endpoint
        if not uri:
            uri = '/api/' + get_model_class_name(cls).lower() + 's'
            LOG.info('treat %s as RESTful URI:%s', get_model_class_name(cls), uri)
        if uri and uri not in __restful_api_wrappers:
            w = RESTfulAPIWraper(uri, cls, title=title, form=form)
            __restful_api_wrappers[uri] = w
            route_pieces = uri.split('/')
            page_name = route_pieces[len(route_pieces)-1]
            __page_descriptor_model_wrappers[page_name] = w
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
            register_model_general_api_handlers(w.cls, endpoint, form=w.form)
    register_model_page_descriptor_api_handler(get_page_descriptor_model)
    __restful_api_registered = True
