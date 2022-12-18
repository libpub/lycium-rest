#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import tornado.web
import tornado.httputil
import sqlalchemy
import i18n
from http import HTTPStatus
from typing import Iterable
from collections.abc import Callable
from wtforms import Form
from hawthorn.asynchttphandler import GeneralTornadoHandler
from hawthorn.modelutils import ModelBase, model_columns, get_model_class_name
from hawthorn.dbproxy import DbProxy
from ..valueobjects.resultcodes import RESULT_CODE
from ..valueobjects.responseobject import GeneralResponseObject

from .restdescriptor import RESTfulAPIWraper
from .utils import read_request_parameters, get_locale_params

LOG = logging.getLogger('services.generalmodelapi.apihandlers')

class ModelPageDescriptorsApiHandler():
    """
    Model page descriptor API handler wrapper
    """
    def __init__(self, get_page_descriptor_model: Callable[[str], RESTfulAPIWraper]):
        self.get_page_descriptor_model = get_page_descriptor_model

    async def handler_get(self, handler: GeneralTornadoHandler, request: tornado.httputil.HTTPServerRequest):
        """
        API handler of get single model data
        """
        filters = read_request_parameters(request)
        locale_params = get_locale_params(request)
        
        result = GeneralResponseObject(RESULT_CODE.DATA_DOES_NOT_EXISTS, message=i18n.t('basic.data_not_exists', **locale_params))
        while result.code != RESULT_CODE.OK:
            page_route = str(filters.get('pathname', ''))
            route_pieces = page_route.split('/')
            if not page_route or not route_pieces:
                result.code = RESULT_CODE.INVALID_PARAM
                result.message = i18n.t('basic.route_path_name_should_not_empty', **locale_params)
                break

            page_name = route_pieces[len(route_pieces)-1]
            w = self.get_page_descriptor_model(page_name)
            if not w:
                result.code = RESULT_CODE.INVALID_PARAM
                result.message = i18n.t('basic.could_not_recognize_current_page', **locale_params)
                break
            if not w.cls:
                result.code = RESULT_CODE.INTERNAL_ERROR
                result.message = f'No model specified for page name: {page_name}' # i18n.t('basic.could_not_recognize_current_page', **locale_params)
                break

            result.code = RESULT_CODE.OK
            result.message = i18n.t('basic.success', **locale_params)
            result.data = w.destriptor()
            break
        
        return result.encode_json()
