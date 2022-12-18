#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import tornado.web
import tornado.httputil
import sqlalchemy
from typing import Iterable
from hawthorn.asynchttphandler import args_as_dict, request_body_as_json
from hawthorn.modelutils import ModelBase, model_columns
from hawthorn.utilities import toint

LOG = logging.getLogger('services.generalmodelapi.utils')

def format_model_query_conditions(model: ModelBase, filters: dict = {}, skip_non_existed_column=True):
    filter_conds = []
    err_messages = []
    if filters:
        for k, v in filters.items():
            if not hasattr(model, k):
                if not skip_non_existed_column:
                    err_messages.append(f'column {k} were not existed')
                continue
            model_field: sqlalchemy.Column = getattr(model, k)
            if isinstance(v, dict):
                for op, cv in v.items():
                    if '<>' == op or '!=' == op or '$ne' == op:
                        filter_conds.append(model_field!=cv)
                    elif '=' == op or '$eq' == op:
                        filter_conds.append(model_field==cv)
                    elif '>' == op or '$gt' == op:
                        filter_conds.append(model_field>cv)
                    elif '>=' == op or '$ge' == op:
                        filter_conds.append(model_field>=cv)
                    elif '<' == op or '$lt' == op:
                        filter_conds.append(model_field<cv)
                    elif '<=' == op or '$le' == op:
                        filter_conds.append(model_field<=cv)
                    elif 'contains' == op:
                        filter_conds.append(model_field.contains(str(cv)))
                    elif 'does not contain' == op:
                        filter_conds.append(model_field.notilike('%' + str(cv) + '%'))
                    elif 'begin with' == op:
                        filter_conds.append(model_field.startswith(str(cv)))
                    elif 'does not begin with' == op:
                        filter_conds.append(model_field.notilike(str(cv) + '%'))
                    elif 'end with' == op:
                        filter_conds.append(model_field.endswith(str(cv)))
                    elif 'does not end with' == op:
                        filter_conds.append(model_field.notilike('%' + str(cv)))
                    elif 'is null' == op or 'isnull' == op:
                        filter_conds.append(model_field.is_(None))
                    elif 'is not null' == op or 'isnotnull' == op:
                        filter_conds.append(model_field.is_not(None))
                    elif 'is empty' == op or 'isempty' == op:
                        filter_conds.append(model_field.is_(None))
                    elif 'is not empty' == op or 'isnotempty' == op:
                        filter_conds.append(model_field.is_not(None))
                    elif 'is between' == op:
                        if isinstance(cv, Iterable) and len(cv > 1):
                            filter_conds.append(model_field.between(cv[0], cv[1]))
                        else:
                            err_messages.append(f'Operator {op} value for column {k} were not iterable or compare values count less than 2')
                    elif 'is not between' == op:
                        if isinstance(cv, Iterable) and len(cv > 1):
                            filter_conds.append(~model_field.between(cv[0], cv[1]))
                        else:
                            err_messages.append(f'Operator {op} value for column {k} were not iterable or compare values count less than 2')
                    elif 'in' == op or 'is in' == 'op' or 'is in list' == 'op':
                        if isinstance(cv, Iterable):
                            filter_conds.append(model_field.in_(cv))
                        else:
                            err_messages.append(f'Operator {op} value for column {k} were not iterable')
                    elif 'not in' == op or 'is not in' == 'op' or 'is not in list' == 'op':
                        if isinstance(cv, Iterable):
                            filter_conds.append(model_field.not_in(cv))
                        else:
                            err_messages.append(f'Operator {op} value for column {k} were not iterable')
                    else:
                        err_messages.append(f'Operator {op} for column {k} were not supported')
                continue
            elif isinstance(v, list):
                filter_conds.append(model_field.in_(v))
            else:
                if model_field.expression.type.__visit_name__ == 'string':
                    filter_conds.append(model_field.contains(str(v)))
                else:
                    filter_conds.append(model_field==v)
    return filter_conds, ', '.join(err_messages)

def dump_model_data(model: ModelBase, columns: list = None):
    values = {}
    if not columns:
        columns, _ = model_columns(model)
    hidden_fields = []
    if hasattr(model, '__hidden_response_fields__') and isinstance(getattr(model, '__hidden_response_fields__', None), list):
        hidden_fields = getattr(model, '__hidden_response_fields__')
    for c in columns:
        if c in hidden_fields:
            continue
        if hasattr(model, c):
            val = getattr(model, c)
            if isinstance(val, bytes):
                val = val.decode('utf-8')
            values[c] = val
    return values

def read_request_parameters(request: tornado.httputil.HTTPServerRequest):
    params = args_as_dict(request)
    if request.method == 'POST':
        if request.headers['Content-Type'] == 'application/json':
            filters2 = request_body_as_json(request)
            for k, v in filters2.items():
                # if body contains the same key besides the query arguments, overwrite it.
                # it means that the post body parameter has the high priority value
                params[k] = v
        else:
            # post body parameters would already parsed in request.arguments
            pass
    if not params:
        params = {}
    return params

def get_locale_params(request: tornado.httputil.HTTPServerRequest):
    locale_params = {}
    language = ''
    if request.headers.get("Accept-Language"):
        languages = request.headers.get("Accept-Language").split(",")
        locales = []
        for language in languages:
            parts = language.strip().split(";")
            if len(parts) > 1 and parts[1].strip().startswith("q="):
                try:
                    score = float(parts[1].strip()[2:])
                    if score < 0:
                        raise ValueError()
                except (ValueError, TypeError):
                    score = 0.0
            else:
                score = 1.0
            if score > 0:
                locales.append((parts[0], score))
        if locales:
            locales.sort(key=lambda pair: pair[1], reverse=True)
            codes = [loc[0] for loc in locales]
            language = codes[0]
    else:
        # for k, v in request.cookies.items():
        #     print('cookie keys:', k, v)
        language = request.cookies.get('locale', None)
        if not language:
            language = request.headers.get('Locale', None)
    if language:
        locale_params['locale'] = str(language)
    return locale_params

def get_listquery_pager_info(params, default_list_limit=20, max_list_limit=1000):
    limit = default_list_limit
    page = 0
    if 'pagesize' in params or 'pageSize' in params:
        limit = toint(params['pagesize' if 'pagesize' in params else 'pageSize'])
        if not limit:
            limit = default_list_limit
        elif limit > max_list_limit:
            limit = max_list_limit
    if 'page' in params or 'current' in params:
        page = toint(params['page' if 'page' in params else 'current']) - 1
        if page < 0:
            page = 0
    offset = page * limit
    return limit, offset

def get_listquery_sort_info(params):
    order = ''
    direction = 'asc'
    sortsParam = params
    if 'sorts' in params and isinstance(params['sorts'], dict):
        sortsParam = params['sorts']
    elif 'sorts' in params and isinstance(params['sorts'], str):
        try:
            sortsParam = json.loads(params['sorts'])
        except:
            pass
    elif 'sorter' in params and isinstance(params['sorter'], str):
        try:
            sortsParam = json.loads(params['sorter'])
            for k, v in sortsParam.items():
                order = k
                direction = 'asc' if v.startswith('asc') else 'desc'
                return order, direction
        except:
            pass

    if 'sort' in sortsParam and isinstance(sortsParam['sort'], str):
        order = sortsParam['sort']
    direction = 'asc'
    for sortOrderKey in ['direction', 'order']:
        if sortOrderKey in sortsParam and isinstance(sortsParam[sortOrderKey], str):
            direction = sortsParam[sortOrderKey].lower()
            if direction != 'desc':
                direction = 'asc'
            break
    if order and order.startswith('-'):
        order = order[1:]
        direction = 'desc'
    return order, direction
