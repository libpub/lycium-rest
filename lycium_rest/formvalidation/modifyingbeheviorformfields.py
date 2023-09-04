#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n
from wtforms import Form, StringField, IntegerField, BooleanField, HiddenField
from wtforms.validators import DataRequired, NumberRange, Length, Regexp, AnyOf
from .validators import DateTimeValidator, DefaultValue
from .formitemprops import FormItemProps
from ..valueobjects import LOCALE_PARAMS

class ModifyingBeheviorFormFields(object):
    'Form validation fields for modifying beheviors'
    obsoleted = IntegerField(label=i18n.t('basic.obsoleted_status', **LOCALE_PARAMS),
        validators=[
            DefaultValue(value=0),
            AnyOf({0: i18n.t('basic.normal', **LOCALE_PARAMS), 1: i18n.t('basic.obsoleted', **LOCALE_PARAMS)}, message=i18n.t('basic.please_select_correct_obsoleted_status', **LOCALE_PARAMS)),
            FormItemProps(hide_in_table=True, hide_in_form=True, hide_in_search=True)
        ])
    createdAt = StringField(label=i18n.t('basic.created_at', **LOCALE_PARAMS), id='created_at',
        validators=[
            DateTimeValidator(allow_empty=True),
            FormItemProps(hide_in_table=True, hide_in_form=True, hide_in_search=True)
        ])
    updatedAt = StringField(label=i18n.t('basic.updated_at', **LOCALE_PARAMS), id='updated_at',
        validators=[
            DateTimeValidator(allow_empty=True),
            FormItemProps(hide_in_table=False, hide_in_form=True, hide_in_search=True)
        ])
    createdBy = HiddenField(label=i18n.t('basic.created_by', **LOCALE_PARAMS), id='created_by',
        validators=[
            FormItemProps(hide_in_table=True, hide_in_form=True, hide_in_search=True)
        ])
    updatedBy = HiddenField(label=i18n.t('basic.updated_by', **LOCALE_PARAMS), id='updated_by',
        validators=[
            FormItemProps(hide_in_table=False, hide_in_form=True, hide_in_search=True)
        ])
