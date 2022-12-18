#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column
from wtforms import Form, Field
from wtforms.validators import DataRequired, NumberRange, Length, Regexp, AnyOf, Email, URL
from hawthorn.modelutils import ModelBase, model_columns, get_model_class_name
from lycium_rest.formvalidation.validators import DateTimeValidator

class RESTfulAPIWraper:
    def __init__(self, endpoint: str, cls: ModelBase, title: str = '', form: Form = None):
        self.endpoint = endpoint
        self.title = title
        self.cls = cls
        self.form = form
        self._descriptor = {}

    def destriptor(self, host: str=''):
        if not self._descriptor:
            self._descriptor = {
                'title': self.title if self.title else '',
                'cardBordered': True,
                'fetchDataURL': host + self.endpoint,
                'saveURL': host + self.endpoint + '/:id',
                'saveURLMethod': 'PATCH',
                'newURL': host + self.endpoint,
                'newURLMethod': 'POST',
                'viewURL': host + self.endpoint + '/:id',
                'viewURLMethod': 'GET',
                'deleteURL': host + self.endpoint + '/:id',
                'deleteURLMethod': 'DELETE',
                'editable': True,
                'rowKey': 'id',
                'pagination': {
                    'pageSize': 10,
                },
                'columns': []
            }
            if self.cls:
                columns, pk = model_columns(self.cls)
                formFieldsMapper = {}
                if self.form:
                    form = self.form()
                    for name, field in form._fields.items():
                        # field: Field = getattr(self.form, name)
                        colname = name
                        if field.id:
                            colname = field.id
                        formFieldsMapper[colname] = field
                            
                self._descriptor['rowKey'] = pk
                self._descriptor['columns'] = [self.generate_column_descriptor(colname, formFieldsMapper) for colname in columns]
        return self._descriptor

    def generate_column_descriptor(self, colname: str, formFieldsMapper: dict[str, Field]):
        column = {
            'key': colname,
            'name': colname,
            'valueType': 'text',
            'formItemProps': {'rules': []},
        }
        colfield: Column = getattr(self.cls, colname)
        if colfield.comment:
            column['description'] = colfield.comment
        if colfield.autoincrement:
            column['hideInForm'] = True
            column['readonly'] = True
            column['hideInSearch'] = True
        elif colfield.index:
            column['hideInSearch'] = False
        if colname in formFieldsMapper:
            field = formFieldsMapper[colname]
            if field.label:
                column['label'] = field.label.text
            if field.description:
                column['description'] = field.description
            for validator in field.validators:
                if isinstance(validator, DataRequired):
                    column['formItemProps']['rules'].append({'required': True, 'message': validator.message})
                elif isinstance(validator, DateTimeValidator):
                    column['valueType'] = 'dateTime'
                    column['sortable'] = True
                elif isinstance(validator, Regexp):
                    column['formItemProps']['rules'].append({'pattern': validator.regex.pattern, 'message': validator.message})
                elif isinstance(validator, Length) or isinstance(validator, NumberRange):
                    if validator.max > 0:
                        column['formItemProps']['rules'].append({'max': validator.max, 'message': validator.message})
                    if validator.min > 0:
                        column['formItemProps']['rules'].append({'min': validator.min, 'message': validator.message})
                    # if isinstance(validator, NumberRange):
                    #     column['valueType'] = 'number'
                elif isinstance(validator, AnyOf):
                    enumValues = validator.values
                    if isinstance(validator.values, dict):
                        column['valueType'] = 'select'
                        column['valueEnum'] = [{'value': k, 'text': v} for k, v in validator.values.items()]
                        enumValues = [k for k, _ in validator.values.items()]
                    column['formItemProps']['rules'].append({'enum': enumValues, 'message': validator.message})
                elif isinstance(validator, Email):
                    column['formItemProps']['rules'].append({'type': 'email', 'message': validator.message})
                elif isinstance(validator, URL):
                    column['formItemProps']['rules'].append({'type': 'url', 'message': validator.message})
        return column
