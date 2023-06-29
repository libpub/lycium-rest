#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

LOCALE_PARAMS = {
    'locale': os.environ.get('LAN', 'zh_CN')
}

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.default(self, obj)
