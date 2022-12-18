#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import tornado.web
import tornado.httputil
import sqlalchemy
import i18n
from http import HTTPStatus
from typing import Iterable
from hawthorn.asynchttphandler import GeneralTornadoHandler, request_body_as_json
from hawthorn.session import TornadoSession
from hawthorn.modelutils import ModelBase, model_columns, get_model_class_name
from hawthorn.dbproxy import DbProxy
from ..valueobjects.resultcodes import RESULT_CODE
from ..valueobjects.responseobject import GeneralResponseObject, ListResponseObject

from .utils import format_model_query_conditions, read_request_parameters, get_locale_params

LOG = logging.getLogger('services.generalmodelapi.apihandlers')

class ModelRelationsRESTfulHandler(tornado.web.RequestHandler):
    """
    Model API many-to-many relationships handler wrapper
    """
    def initialize(self, middle_model: ModelBase, src_field: str, dst_field: str, src_model: ModelBase, dst_model: ModelBase, ac=[]):
        self.middle_model = middle_model
        self.src_field = src_field
        self.dst_field = dst_field
        self.src_model = src_model
        self.dst_model = dst_model
        if not getattr(self.middle_model, self.src_field):
            LOG.error('initialize %s middle relations api handler failed, there is no %s field in model', get_model_class_name(self.middle_model), self.src_field)
        if not getattr(self.middle_model, self.dst_field):
            LOG.error('initialize %s middle relations api handler failed, there is no %s field in model', get_model_class_name(self.middle_model), self.dst_field)
        self._ac = []
        self.session = TornadoSession(self)
        self.set_access_control(ac)

    def set_access_control(self, ac):
        self._ac = []
        if ac:
            if isinstance(ac, list):
                for f in ac:
                    if callable(f):
                        self._ac.append(['', f])
            elif isinstance(ac, dict):
                for k, f in ac:
                    if callable(f):
                        self._ac.append([k, f])
            elif callable(ac):
                self._ac.append(['', ac])

    def pre_check_middle_model_fields(self, **kwargs):
        if not hasattr(self.middle_model, self.src_field) or not hasattr(self.middle_model, self.dst_field):
            err_message = '%s or %s filed does not exists in relation model' % (self.src_field, self.dst_field)
            return err_message
        return ''

    async def get(self, instanceID: str|int = None):
        """
        API handler of get many-to-many relationships ids
        """
        if not instanceID:
            self.set_status(HTTPStatus.NOT_FOUND)
            self.finish()
            return
        locale_params = get_locale_params(self.request)
        err_message = self.pre_check_middle_model_fields(**locale_params)
        if err_message:
            LOG.error('failed to execute handler of get %s relations id, %s', get_model_class_name(self.middle_model), err_message)
            self.set_status(HTTPStatus.INTERNAL_SERVER_ERROR, err_message)
            self.finish()
            return
        filters = read_request_parameters(self.request)
        filters[self.src_field] = instanceID
        dst_field: sqlalchemy.Column = None
        if self.src_field in filters:
            dst_field = getattr(self.middle_model, self.dst_field)
        elif self.dst_field in filters:
            dst_field = getattr(self.middle_model, self.src_field)
        
        result = ListResponseObject(RESULT_CODE.DATA_DOES_NOT_EXISTS, message=i18n.t('basic.data_not_exists', **locale_params))
        while result.code != RESULT_CODE.OK:
            filter_conds, err_msg = format_model_query_conditions(self.middle_model, filters=filters)
            if err_msg:
                result.code = RESULT_CODE.INVALID_PARAM
                result.message = err_msg
                break

            limit = 1000
            offset = 0
            rows, total = await DbProxy().query_list(self.middle_model, filters=filter_conds, limit=limit, offset=offset, selections=[dst_field.name])
            result.code = RESULT_CODE.OK
            result.message = i18n.t('basic.success', **locale_params)
            result.total = total
            result.data = rows
            if limit:
                result.pageSize = limit
                result.page = int(offset/limit) + 1
        self.set_header('Content-Type', 'application/json')
        self.write(result.encode_json())
        self.finish()

    async def post(self, instanceID: str|int = None):
        """
        API handler of add many-to-many relationships
        """
        await self.common_update_relations(instanceID, 'add')

    async def patch(self, instanceID: str|int = None):
        """
        API handler of update many-to-many relationships ids
        """
        await self.common_update_relations(instanceID, 'update')

    async def delete(self, instanceID: str|int = None):
        """
        API handler of delete delete many-to-many relationships ids
        """
        if not instanceID:
            self.set_status(HTTPStatus.NOT_FOUND)
            self.finish()
            return
        locale_params = get_locale_params(self.request)
        err_message = self.pre_check_middle_model_fields(**locale_params)
        if err_message:
            LOG.error('failed to execute handler of delete %s relations id, %s', get_model_class_name(self.middle_model), err_message)
            self.set_status(HTTPStatus.INTERNAL_SERVER_ERROR, err_message)
            self.finish()
            return
        inputs = request_body_as_json(self.request)
        inputs[self.src_field] = instanceID
        src_value = inputs.get(self.src_field, 0)
        dst_value = inputs.get(self.dst_field, 0)
        result = GeneralResponseObject(RESULT_CODE.INVALID_PARAM, i18n.t('basic.invalid_param', **locale_params))
        while result.code != RESULT_CODE.OK:
            check_fields = [(self.src_model, self.src_field, src_value), (self.dst_model, self.dst_field, dst_value)]
            check_failed = False
            for cks in check_fields:
                if not cks[2]:
                    result.code = RESULT_CODE.INVALID_PARAM
                    result.message = '%s field should have a valid value' % (cks[1])
                    LOG.warning('delete relation ids for %s failed, %s', get_model_class_name(self.middle_model), result.message)
                    check_failed = True
                    break
            if check_failed:
                break

            try:
                del_conds = [
                    self.format_relation_find_conditions(self.middle_model, self.src_field, src_value)[0],
                    self.format_relation_find_conditions(self.middle_model, self.dst_field, dst_value)[0]
                ]
                res = await DbProxy().del_items(self.middle_model, del_conds)
                if res:
                    result.code = RESULT_CODE.OK
                    result.message = i18n.t('basic.success', **locale_params)
                    LOG.info('delete relation ids for %s with %s:%s and %s:%s succeed, affected %d rows', get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value), res)
                else:
                    result.code = RESULT_CODE.DATA_DOES_NOT_EXISTS
                    result.message = i18n.t('basic.data_not_exists', **locale_params)
                    LOG.warning('delete relation ids for %s with %s:%s and %s:%s affected zero rows', get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value))
            except Exception as e:
                LOG.error('delete relation ids for %s with %s:%s and %s:%s failed with error:%s', get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value), str(e))
                result.code = RESULT_CODE.FAIL
                result.message = str(e)
            break
        self.set_header('Content-Type', 'application/json')
        self.write(result.encode_json())
        self.finish()

    async def common_update_relations(self, instanceID: str|int, mode: str):
        """
        common relation ids operator of many-to-many relationships ids
        """
        if not instanceID:
            self.set_status(HTTPStatus.NOT_FOUND)
            self.finish()
            return
        locale_params = get_locale_params(self.request)
        err_message = self.pre_check_middle_model_fields(**locale_params)
        if err_message:
            LOG.error('failed to execute handler of %s %s relations id, %s', mode, get_model_class_name(self.middle_model), err_message)
            return err_message, HTTPStatus.INTERNAL_SERVER_ERROR
        inputs = request_body_as_json(self.request)
        inputs[self.src_field] = instanceID
        src_value = inputs.get(self.src_field, 0)
        dst_value = inputs.get(self.dst_field, 0)
        extra_field_values = {}
        middle_model_columns, middle_model_pk = model_columns(self.middle_model)
        for k in middle_model_columns:
            if k == middle_model_pk:
                continue
            if k in inputs and k != self.src_field and k != self.dst_field:
                extra_field_values[k] = inputs[k]

        result = GeneralResponseObject(RESULT_CODE.INVALID_PARAM, i18n.t('basic.invalid_param', **locale_params))
        while result.code != RESULT_CODE.OK:
            check_models = [(self.src_model, self.src_field, src_value), (self.dst_model, self.dst_field, dst_value)]
            check_failed = False
            for cks in check_models:
                if not cks[2]:
                    result.code = RESULT_CODE.INVALID_PARAM
                    result.message = '%s field should have a valid value' % (cks[1])
                    LOG.warning('%s relation ids for %s failed, %s', mode, get_model_class_name(self.middle_model), result.message)
                    check_failed = True
                    break
                if cks[0]:
                    try:
                        _, pk = model_columns(cks[0])
                        check_conds = self.format_relation_find_conditions(cks[0], pk, cks[2])
                        src_exists = await DbProxy().get_count(cks[0], check_conds)
                        if not src_exists:
                            result.code = RESULT_CODE.DATA_DOES_NOT_EXISTS
                            result.message = get_model_class_name(cks[0]) + f' by {cks[2]} does not exists'
                            LOG.warning('add relation ids for %s failed, %s', get_model_class_name(self.middle_model), result.message)
                            check_failed = True
                            break
                    except Exception as e:
                        result.code = RESULT_CODE.INVALID_PARAM
                        result.message = str(e)
                        LOG.warning('add relation ids for %s failed, %s', get_model_class_name(self.middle_model), result.message)
                        check_failed = True
                        break
            if check_failed:
                break

            adding_datas = []
            exists_records = {}
            src_ids = [v for v in src_value] if isinstance(src_value, Iterable) else [src_value]
            dst_ids = [v for v in dst_value] if isinstance(dst_value, Iterable) else [dst_value]
            for v1 in src_ids:
                for v2 in dst_ids:
                    adding_datas.append((v1, v2))
            if 'add' != mode:
                try:
                    exists_rows = await DbProxy().query_all(self.middle_model, self.format_relation_find_conditions(self.middle_model, self.src_field, src_value))
                    for ele in exists_rows:
                        exists_records[f'{ele[self.src_field]}-{ele[self.dst_field]}'] = ele
                except Exception as e:
                    result.code = RESULT_CODE.INVALID_PARAM
                    result.message = str(e)
                    LOG.warning('%s relation ids for %s while find existing records by %s:%s failed, %s', mode, get_model_class_name(self.middle_model), self.src_field, str(src_value), result.message)
                    break
            add_records = []
            for ele in adding_datas:
                m = self.middle_model()
                if hasattr(m, 'set_session_uid'):
                    session_uid = self.session['user_id']
                    setattr(m, 'set_session_uid', session_uid)
                setattr(m, self.src_field, ele[0])
                setattr(m, self.dst_field, ele[1])
                for k, v in extra_field_values.items():
                    setattr(m, k, v)
                add_records.append(m)
                existing_key = f'{ele[0]}-{ele[1]}'
                if existing_key in exists_records:
                    del exists_records[existing_key]

            del_records_conds = []
            del_ids = [row[middle_model_pk] for row in exists_records.values()]
            if del_ids:
                del_records_conds.append(getattr(self.middle_model, middle_model_pk).in_(del_ids))

            try:
                LOG.info('%s relation ids for %s adding records with %s:%s and %s:%s', mode, get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value))
                res = await DbProxy().insert_items(add_records, auto_flush=True)
                if res:
                    result.code = RESULT_CODE.OK
                    result.message = i18n.t('basic.success', **locale_params)
                    LOG.info('%s relation ids for %s adding records with %s:%s and %s:%s succeed', mode, get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value))

                    if del_ids:
                        LOG.info('%s relation ids for %s deleting old relation records %s', mode, get_model_class_name(self.middle_model), str(del_ids))
                        del_count = await DbProxy().del_items(self.middle_model, del_records_conds)
                        LOG.info('%s relation ids for %s deleting old relation records %s affected %d rows', mode, get_model_class_name(self.middle_model), str(del_ids), del_count)
                else:
                    LOG.error('%s relation ids for %s with %s:%s and %s:%s failed', mode, get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value))
            except Exception as e:
                LOG.error('%s relation ids for %s with %s:%s and %s:%s failed with error:%s', mode, get_model_class_name(self.middle_model), self.src_field, str(src_value), self.dst_field, str(dst_value), str(e))
                result.code = RESULT_CODE.FAIL
                result.message = str(e)
            break
        self.set_header('Content-Type', 'application/json')
        self.write(result.encode_json())
        self.finish()

    def format_relation_find_conditions(self, model: ModelBase, field_name:str, find_value):
        conds = []
        if isinstance(find_value, dict) or isinstance(find_value, list) or isinstance(find_value, tuple):
            conds.append(getattr(model, field_name).in_(find_value))
        else:
            conds.append(getattr(model, field_name)==find_value)
        return conds
