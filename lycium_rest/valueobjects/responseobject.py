#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from .resultcodes import RESULT_CODE
from . import JsonEncoder

class GeneralResponseObject(object):
    """
    General Response Object
    """
    class GeneralResponseObjectError(TypeError):
        pass

    def __init__(self, code=-2, message='Unsupported operation'):
        self.code = code
        self.data = None
        self.message = message

    def is_success(self):
        return self.code == RESULT_CODE.OK

    def as_dict(self):
        result = {
            'code': self.code,
            'message': self.message
        }
        if self.data is not None:
            result['data'] = self.data
        return result

    def encode_json(self):
        obj = self.as_dict()
        return json.dumps(obj, cls=JsonEncoder)

class ListResponseObject(object):
    """
    List Data Response Object
    """
    class ListResponseObjectError(TypeError):
        pass

    def __init__(self, code=-2, message='Unsupported operation'):
        self.code = code
        self.total = 0
        self.page = 0
        self.pageSize = 0
        self.data = []
        self.message = message

    def is_success(self):
        return self.code == RESULT_CODE.OK

    def as_dict(self):
        result = {
            'code': self.code,
            'total': self.total,
            'page': self.page,
            'pageSize': self.pageSize,
            'data': self.data,
            'message': self.message
        }
        return result

    def encode_json(self):
        obj = self.as_dict()
        return json.dumps(obj, cls=JsonEncoder)
