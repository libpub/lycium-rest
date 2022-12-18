#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n
from wtforms import Form
from hawthorn.modelutils import ModelBase, model_columns
from ..valueobjects.resultcodes import RESULT_CODE
from ..valueobjects.responseobject import GeneralResponseObject

def prepare_item_fields(form_item: Form):
    # if not fields or not isinstance(fields, dict):
    #     if isinstance(fields, list):
    #         return { v: v for v in fields }
    #     rfields = {}
    #     default_cols, pk = model_columns(self.model)
    #     for col in default_cols:
    #         if col != pk and col not in DEFAULT_SKIP_FIELDS:
    #             rfields[col] = col
    #     return rfields
    # return fields
    rfields = {}
    for field in form_item:
        if field.name not in rfields and not field.flags.hidden:
            rfields[field.name] = field.id if field.id else field.name

    return rfields

def save_form_fields(form_item: Form, model: ModelBase, ignore_empty=True):
    columns, pk = model_columns(model)
    for field in form_item:
        field_name = field.id if field.id else field.name
        if field_name == pk:
            continue
        if hasattr(model, field_name):
            if not field.data:
                if ignore_empty and isinstance(field.data, str) or isinstance(field.data, bytes):
                    continue
            # if model has set_<property> method, call set_<property> to set model field data
            if hasattr(model, 'set_' + field_name) and callable(getattr(model, 'set_' + field_name, None)):
                getattr(model, 'set_' + field_name)(field.data)
            else:
                setattr(model, field_name, field.data)

def validate_form(form_item: Form, **kwargs):
    """
    Validate form data
    @param form_item: Form input data
    @param locale=en_US [optional]
    """
    locale_params = {}
    language = kwargs.pop('locale', None)
    if language:
        locale_params['locale'] = language
    if not form_item.validate():
        errs = form_item.errors
        if errs:
            errslices = []
            for errelements in errs.values():
                errslices.append(';'.join(errelements))
            errtext = ';'.join(errslices)
        else:
            errtext = i18n.t('basic.invalid_param', **locale_params)
        return GeneralResponseObject(RESULT_CODE.INVALID_PARAM, errtext)
    return GeneralResponseObject(RESULT_CODE.OK, message=i18n.t('basic.success', **locale_params))
