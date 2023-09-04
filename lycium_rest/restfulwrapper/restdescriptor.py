#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n
from sqlalchemy import Column
from sqlalchemy.orm import class_mapper
from wtforms import Form, Field, FieldList, FormField
from wtforms.validators import DataRequired, NumberRange, Length, Regexp, AnyOf, Email, URL
from hawthorn.modelutils import ModelBase, model_columns, get_model_class_name
from lycium_rest.formvalidation.validators import DataDictsValidator, DataExistsValidator, DateTimeValidator, DefaultValue, RequiredDependencyField
from lycium_rest.formvalidation.formitemprops import FormItemProps
from .utils import find_model_class_by_cls_name

__restful_apis_by_model_name: dict[str, str] = {}

def set_restful_api_by_model(model_name: str, uri: str):
    __restful_apis_by_model_name[model_name] = uri

def get_restful_api_by_model(model: ModelBase):
    model_name = model if isinstance(model, str) else get_model_class_name(model)
    return __restful_apis_by_model_name.get(model_name, '/api/' + model_name.lower() + 's')

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
            self.generate_columns_descriptors(self._descriptor, self.cls, self.form, host, locale_params)
            
        return self._descriptor
    
    def generate_columns_descriptors(self, descriptor: dict, model_cls: ModelBase, form_cls: Form, host: str='', locale_params: dict = {}, as_group: bool = False):
        columnsDescriptors: list = []
        columns = []
        formFieldsMapper = {}
        if model_cls:
            columns, pk = model_columns(model_cls)
            # formFieldsMapper = {}
            # if form_cls:
            #     form = form_cls()
            #     formFieldsMapper = {name: field for name, field in form._fields.items()}
            #     columns = form._fields.keys()
            formFieldsMapper = {colname: None for colname in columns}
            descriptor['rowKey'] = pk
            
        ex_column_props = {}
        if form_cls:
            form = form_cls()
            for name, field in form._fields.items():
                colname = name
                if field.id:
                    colname = field.id
                if colname not in formFieldsMapper:
                    columns.append(colname)
                formFieldsMapper[colname] = field
            if hasattr(form_cls, 'form_layout_props'):
                for k, v in getattr(form_cls, 'form_layout_props', {}).items():
                    descriptor[k] = v
            if hasattr(form_cls, 'column_layout_props'):
                ex_column_props = getattr(form_cls, 'column_layout_props', {})
        
        columnsDescriptors = [self.generate_column_descriptor(model_cls, colname, formFieldsMapper, host=host, locale_params=locale_params, ex_column_props=ex_column_props) for colname in columns]
        
        if model_cls:
            for attrtype in model_cls.__dict__.values():
                if isinstance(attrtype, Operations):
                    columnsDescriptors.append(attrtype.destriptor(host=host, locale_params=locale_params))
        
        if as_group:
            descriptor['columns'] = [{'valueType': 'group', 'columns': columnsDescriptors}]
        else:
            descriptor['columns'] = columnsDescriptors

    def generate_column_descriptor(self, model_cls: ModelBase, colname: str, formFieldsMapper: dict[str, Field], host: str='', locale_params: dict = {}, ex_column_props: dict = {}):
        column = {
            'key': colname,
            'name': colname,
            'valueType': 'text',
            'formItemProps': {'rules': []},
        }
        if ex_column_props:
            for k, v in ex_column_props.items():
                column[k] = v
        if hasattr(model_cls, colname):
            colfield: Column = getattr(model_cls, colname)
            if colfield.comment:
                column['description'] = colfield.comment
            if colfield.autoincrement:
                if isinstance(colfield.autoincrement, bool) or colfield.primary_key:
                    column['hideInForm'] = True
                    column['readonly'] = True
                    column['hideInSearch'] = True
            elif colfield.index:
                column['hideInSearch'] = False
        else:
            column['hideInTable'] = True
            column['hideInSearch'] = True
        colformfield: Field = formFieldsMapper.get(colname, None)
        if colformfield is not None:
            self._format_column_with_form_field(column, colformfield, host=host, locale_params=locale_params)
            
        return column
    
    def _format_column_with_form_field(self, column: dict, field: Field, host: str='', locale_params: dict = {}):
        if field.id != field.name:
            column['key'] = field.id
        if field.label:
            column['label'] = field.label.text
        # print(' ---- field:%s field:Type:%s', field.name, field.type)
        if field.type == 'IntegerField':
            column['valueType'] = 'digit'
        elif field.type == 'FieldList':
            column['valueType'] = 'formList'
            column['colSize'] = 2
            # print(' >>>> field:%s field form' % (field.name), field.unbound_field, field.unbound_field.field_class)
            if field.unbound_field is not None:
                self.generate_columns_descriptors(column, None, field.unbound_field.args[0], host, locale_params, as_group=True)
        elif field.type == 'BooleanField':
            column['valueType'] = 'switch'
        if field.description:
            column['description'] = field.description
        for validator in field.validators:
            self._format_column_form_item_props_with_validator(column, validator)
    
    def _format_column_form_item_props_with_validator(self, column: dict, validator: object):
        if isinstance(validator, DataRequired):
            column['formItemProps']['rules'].append({'required': True, 'message': validator.message})
        elif isinstance(validator, DateTimeValidator):
            column['valueType'] = 'dateTime'
            column['sortable'] = True
        elif isinstance(validator, DataDictsValidator):
            column['valueType'] = 'select'
            column['valueEnum'] = [{'value': k, 'text': v} for k, v in validator.values.items()]
            enumValues = [k for k, _ in validator.values.items()]
            column['formItemProps']['rules'].append({'enum': enumValues, 'message': validator.message})
        elif isinstance(validator, DataExistsValidator):
            column['valueType'] = 'select'
            column['request'] = get_restful_api_by_model(validator.model)
            column['asyncSelectOptionLabelField'] = validator.name_field
            column['asyncSelectOptionValueField'] = validator.index_field
        elif isinstance(validator, Email):
            column['formItemProps']['rules'].append({'type': 'email', 'message': validator.message})
        elif isinstance(validator, URL):
            column['formItemProps']['rules'].append({'type': 'url', 'message': validator.message})
        elif isinstance(validator, Regexp):
            column['formItemProps']['rules'].append({'pattern': validator.regex.pattern, 'message': validator.message})
        elif isinstance(validator, Length) or isinstance(validator, NumberRange):
            if validator.max != 0 or validator.min != 0:
                range_rule = {'message': validator.message}
                if validator.max is not None:
                    range_rule['max'] = validator.max
                if validator.min is not None:
                    range_rule['min'] = validator.min
                column['formItemProps']['rules'].append(range_rule)
            if isinstance(validator, NumberRange):
                column['valueType'] = 'digit'
        elif isinstance(validator, AnyOf):
            enumValues = validator.values
            if isinstance(validator.values, dict):
                column['valueType'] = 'select'
                column['valueEnum'] = [{'value': k, 'text': v} for k, v in validator.values.items()]
                enumValues = [k for k, _ in validator.values.items()]
            column['formItemProps']['rules'].append({'enum': enumValues, 'message': validator.message})
        elif isinstance(validator, DefaultValue):
            column['initialValue'] = validator.value
        elif isinstance(validator, RequiredDependencyField):
            dep_required_rule = {
                'required': {
                    'depends': [
                        {
                            'field': validator.field_name,
                            'value': validator.match_value,
                        }
                    ],
                    'message': validator.message,
                },
            }
            column['formItemProps']['rules'].append(dep_required_rule)
        elif isinstance(validator, FormItemProps):
            self._format_column_normal_form_item_props(column, validator)
    
    def _format_column_normal_form_item_props(self, column: dict, props: FormItemProps):
        if props.password:
            column['valueType'] = 'password'
            column['hideInTable'] = True
            column['hideInSearch'] = True
        if props.hide_in_form:
            column['hideInForm'] = True
            column['readonly'] = True
        if props.hide_in_search:
            column['hideInSearch'] = True
        if props.hide_in_table:
            column['hideInTable'] = True
        if props.row_props:
            column['rowProps'] = props.row_props
        if props.col_props:
            column['colProps'] = props.col_props
        if props.dependencies:
            column['dependencies'] = props.dependencies

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
