#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n
from sqlalchemy import Column
from sqlalchemy.orm import class_mapper
from wtforms import Form, Field
from wtforms.validators import DataRequired, NumberRange, Length, Regexp, AnyOf, Email, URL
from hawthorn.modelutils import ModelBase, model_columns, get_model_class_name
from lycium_rest.formvalidation.validators import DateTimeValidator
from .utils import find_model_class_by_cls_name

class Relations:
    def __init__(self, middle_model: ModelBase, src_field: str, dst_field: str, dst_model: ModelBase):
        self.src_field = src_field
        self.dst_field = dst_field
        self.middle_model = middle_model
        self.dst_model = dst_model
        
    def set_src_model(self, src_model):
        self.src_model = src_model
        
    def prepare(self):
        if isinstance(self.middle_model, str):
            middle_model = find_model_class_by_cls_name(self.middle_model)
            if middle_model is None:
                raise Exception("Could not find declared '%s' model class" % (self.middle_model))
            else:
                self.middle_model = middle_model
        if isinstance(self.dst_model, str):
            dst_model = find_model_class_by_cls_name(self.dst_model)
            if dst_model is None:
                raise Exception("Could not find declared '%s' model class" % (self.dst_model))
            else:
                self.dst_model = dst_model

class RESTfulAPIWraper:
    def __init__(self, endpoint: str, cls: ModelBase, title: str = '', form: Form = None, auto_association: str| list[str] = None, custom_relations: Relations | list[Relations] = None):
        self.endpoint = endpoint
        self.title = title
        self.cls = cls
        self.form = form
        self._descriptor = {}
        self._auto_association = auto_association
        self._custom_relations = custom_relations

    def destriptor(self, host: str='', locale_params: dict = {}):
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
            # has_operations = False
            for attrtype in self.cls.__dict__.values():
                if isinstance(attrtype, Operations):
                    self._descriptor['columns'].append(attrtype.destriptor(host=host, locale_params=locale_params))
            #         has_operations = True
            # if not has_operations:
            #     self._descriptor['columns'].append(Operations([Operations.VIEW, Operations.ADD, Operations.EDIT, Operations.DELETE]).destriptor(host=host, locale_params=locale_params))
                
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

class Operations:
    """Defines model record operations for frontend page, this defination would filled in 
    """
    
    ADD = 'add'
    EDIT = 'edit'
    VIEW = 'view'
    DELETE = 'delete'
    
    def __init__(self, operations: list[dict]):
        self.operations = operations
    
    def destriptor(self, host: str='', locale_params: dict = {}):
        operation_descriptor = {
            'key': 'option',
            'name': i18n.t('basic.operation', **locale_params),
            'label': i18n.t('basic.operation', **locale_params),
            'valueType': 'option',
            'hideInSearch': True,
            'operations': []
        }
        for o in self.operations:
            opt = {}
            if isinstance(o, str):
                if o == self.ADD:
                    opt = {'title': i18n.t('basic.add', **locale_params), 'action': 'add'}
                elif o == self.EDIT:
                    opt = {'title': i18n.t('basic.edit', **locale_params), 'action': 'update'}
                elif o == self.VIEW:
                    opt = {'title': i18n.t('basic.view', **locale_params), 'action': 'view'}
                elif o == self.DELETE:
                    opt = {'title': i18n.t('basic.delete', **locale_params), 'action': 'delete'}
            elif isinstance(o, dict):
                opt = o.copy()
            if opt:
                operation_descriptor['operations'].append(opt)
        return operation_descriptor
