#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hawthorn.utilities import Constant

class _ResultCode(Constant):
    # 通过
    OK = 0
    # 失败
    FAIL = -1
    # 参数非法
    INVALID_PARAM = -2
    # 数据不存在
    DATA_DOES_NOT_EXISTS = 103
    # 数据已存在
    DAT_ALREADY_EXISTS = 104
    # 没有新数据可保存
    NOTHING_TO_SAVE = 105
    INTERNAL_ERROR = 500

    # 密码错误
    PASSWORD_NOT_CORRECT = 110011
    # 账户过期
    ACCOUNT_EXPIRED = 110012
    # 账户被冻结
    ACCOUNT_WERE_FROZEN = 110013

RESULT_CODE = _ResultCode()
