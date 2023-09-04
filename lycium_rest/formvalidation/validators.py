#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n
from wtforms.validators import StopValidation, ValidationError, Regexp
import asyncio
import threading
from tornado.ioloop import IOLoop
import tornado.concurrent
import importlib
from hawthorn.dbproxy import DbProxy
from hawthorn.modelutils import meta_data, ModelBase, MongoBase
from hawthorn.utilities import toint, tofloat, get_package_name
from ..valueobjects import LOCALE_PARAMS

class DataExistsValidator(object):
    """
    验证数据是否存在

    :param model:
        The model to be checked.
    :param index_field:
        The field to be checked.
    :param name_field:
        The field to be displayed.
    :param message:
        Error message to raise in case of a validation error.
    """

    def __init__(self, model, index_field='id', name_field='name', 
                 message=None, 
                 should_exists=True, 
                 allows_empty=False,
                 ignore_obsoleted=False,
                 reference_field='id',
                 primary_field='id',
                 union_field=None,
                 fixed_field=None):
        self.model = model
        self.index_field = index_field
        self.name_field = name_field
        self.reference_field = reference_field
        self.primary_field = primary_field
        self.union_field = union_field
        self.fixed_field = fixed_field or {}
        self.message = message
        self.should_exists = should_exists
        self.allows_empty = allows_empty
        self.ignore_obsoleted = ignore_obsoleted

    def __call__(self, form, field):
        if not field.data or isinstance(field.data, str) and not field.data.strip():
            if self.allows_empty:
                return
            if self.message is None:
                message = field.gettext('This field is required.')
            else:
                message = self.message

            field.errors[:] = []
            raise StopValidation(message)
        else:
            model = self.get_validate_model(form)
            index_field = self.get_validate_index_field(form)
            primary = (getattr(form, self.primary_field, None) and getattr(form, self.primary_field).data) or ''
            union = [{'field': field, 'data': (getattr(form, field, None) and getattr(form, field).data or '')} for field in self.union_field] if self.union_field else None
            if not model or not index_field:
                message = 'Field:%s value:%s not valid.' % (self.reference_field, str(getattr(form, self.reference_field).data))
                field.errors[:] = []
                raise StopValidation(message)
            if isinstance(model, MongoBase.my_metaclass):
                mongo_condition = {**self.fixed_field, index_field: field.data}
                if not self.ignore_obsoleted:
                    if hasattr(model, 'obsoleted'):
                        mongo_condition['obsoleted'] = False
                if primary:
                    mongo_condition[self.primary_field + '__ne'] = primary
                if union:
                    for u in union:
                        if u.get('field') and u.get('data'):
                            mongo_condition[u.get('field')] = u.get('data')
                try:
                    val = self.fetch_async_result(DbProxy().query_all_mongo(model, mongo_condition))
                except Exception as e:
                    field.errors[:] = []
                    raise StopValidation(str(e))
            elif issubclass(model, ModelBase):
                pg_condition = [getattr(model, index_field) == field.data]
                if self.fixed_field:
                    for key, value in self.fixed_field.items():
                        if hasattr(model, key):
                            pg_condition.append(getattr(model, key) == value)
                if not self.ignore_obsoleted:
                    if hasattr(model, 'obsoleted'):
                        pg_condition.append(getattr(model, 'obsoleted') == 0)
                if primary:
                    pg_condition.append(getattr(model, self.primary_field) != primary)
                if union:
                    for u in union:
                        if u.get('field') and u.get('data'):
                            pg_condition.append(getattr(model, u.get('field')) == u.get('data'))
                try:
                    val = self.fetch_async_result(DbProxy().find_item(model, pg_condition))
                except Exception as e:
                    field.errors[:] = []
                    raise StopValidation(str(e))

            message = None
            if self.should_exists:
                if not val:
                    if self.message:
                        message = self.message
                    else:
                        message = field.gettext('The field data does not exists.')
            else:
                if val:
                    if self.message:
                        message = self.message
                    else:
                        message = field.gettext('The data should not exists.')

            if message:
                field.errors[:] = []
                raise StopValidation(message)
        
    def get_validate_model(self, form):
        model = self.model
        if isinstance(model, dict):
            if getattr(form, self.reference_field).data in model:
                model = model[getattr(form, self.reference_field).data]
            else:
                return None
        elif isinstance(model, str):
            model_package = get_package_name(model)
            model_names = model.split('.')
            model_name = model_names[len(model_names)-1] if model_names else ''
            if model_package:
                module_package = importlib.import_module(model_package)
                module = getattr(module_package, model_name, None)
                if not module:
                    print('Error: could not find module:%s in package:%s' % (model_name, model_package))
                return module
            else:
                print('Warning: could not find package name by module:%s' % (model_name))
        return model
    
    def get_validate_index_field(self, form):
        index_field = self.index_field
        if isinstance(index_field, dict):
            if getattr(form, self.reference_field).data in index_field:
                index_field = index_field[getattr(form, self.reference_field).data]
            else:
                return None
        return index_field
    
    def get_validate_name_field(self, form):
        name_field = self.name_field
        if isinstance(name_field, dict):
            if getattr(form, self.reference_field).data in name_field:
                name_field = name_field[getattr(form, self.reference_field).data]
            else:
                return None
        return name_field
    
    def fetch_async_result(self, async_task):
        # loop = IOLoop.current().asyncio_loop
        # if loop.is_running():
        #     print('------- run_coroutine_threadsafe')
        #     future = asyncio.run_coroutine_threadsafe(async_task, loop)
        #     print('------- future.result')
        #     sync_result = future.result()
        #     print('------- fetched result')
        # else:
        #     sync_result = loop.run_until_complete(async_task)
        
        future = tornado.concurrent.Future()
        event = threading.Event()

        def set_result():
            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(async_task)
                future.set_result(result)
                loop.close()
                event.set()  # Signal that the result has been set
            except Exception as e:
                future.set_exception(e)
                event.set()  # Signal that an exception occurred

        thread = threading.Thread(target=set_result)
        thread.start()
        event.wait()  # Wait until the result is set or an exception occurs
        sync_result = future.result()

        # sync_result = IOLoop.current().run_sync(async_task)
        # Create a Future to hold the result
        # future = tornado.concurrent.Future()
        # # Callback function to set the result in the Future
        # def set_result():
        #     result = async_task
        #     future.set_result(result)
        # IOLoop.current().add_callback(set_result)

        # # Wait for the result in a synchronous manner
        # sync_result = future.result()
        # sync_result = asyncio.get_event_loop().run_until_complete(async_task)
        return sync_result
    
class DataDictsValidator(object):
    """
    验证数据字典是否合法，并可根据字典值为名称为数据查询拼装名称

    :param dicts:
        The dict to be checked.
    :param message:
        Error message to raise in case of a validation error.
    """

    def __init__(self, dicts, 
                 message=None,
                 multi_dicts=False,
                 values_formatter=None, 
                 should_exists=True, 
                 allows_empty=False,
                 reference_field='id'):
        self.values = dicts
        self.multi_dicts = multi_dicts
        self.message = message
        if values_formatter is None:
            values_formatter = self.default_values_formatter
        self.values_formatter = values_formatter
        self.should_exists = should_exists
        self.allows_empty = allows_empty
        self.reference_field = reference_field

    def __call__(self, form, field):
        if not field.data or isinstance(field.data, str) and not field.data.strip():
            if self.allows_empty:
                return
            if self.message is None:
                message = field.gettext('This field is required.')
            else:
                message = self.message

            field.errors[:] = []
            raise StopValidation(message)
        else:
            values = self.get_validate_model(form)
            if not values:
                message = 'Field:%s value:%s not valid.' % (self.reference_field, str(getattr(form, self.reference_field).data))
                field.errors[:] = []
                raise StopValidation(message)
                
            if field.data not in self.values:
                message = self.message
                if message is None:
                    message = field.gettext('Invalid value, must be one of: %(values)s.')

                raise ValidationError(message % dict(values=self.values_formatter(self.values)))
    
    @staticmethod
    def default_values_formatter(values):
        return ', '.join(str(x) for x in values.keys())

    def get_validate_model(self, form):
        values = self.values
        if self.multi_dicts:
            if getattr(form, self.reference_field).data in values:
                values = values[getattr(form, self.reference_field).data]
            else:
                return None
        return values

class PositiveRealValidators(object):
    """
    验证IntegerFiled 是否为正实数
    """
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        try:
            d = toint(field.data)
        except ValueError as e:
            d = tofloat(field.data)
        if d < 0:
            if self.message is None:
                message = field.gettext('This field is required positive integer.')
            else:
                message = self.message

            field.errors[:] = []
            raise StopValidation(message)

class DateTimeValidator(Regexp):
    """
    Validates the field against a user provided regexp.

    :param regex:
        The regular expression string to use. Can also be a compiled regular
        expression pattern.
    :param flags:
        The regexp flags to use, for example re.IGNORECASE. Ignored if
        `regex` is not a string.
    :param allow_empty:
        If the field allows empty
    :param message:
        Error message to raise in case of a validation error.
    """

    def __init__(self, regex=r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', flags=0, allow_empty=False, message=None):
        super().__init__(regex, flags, message)
        self.allow_empty = allow_empty

    def __call__(self, form, field, message=None):
        if self.allow_empty and not field.data:
            return True
        match = self.regex.match(field.data or "")
        if match:
            return match

        if message is None:
            if self.message is None:
                message = field.gettext("Invalid datetime format.")
            else:
                message = self.message

        raise ValidationError(message)

class DefaultValue():
    """Specifies default value for input field
    """
    
    def __init__(self, value: any):
        self.value = value

    def __call__(self, form, field, message=None):
        if field.data is None:
            field.data = self.value
            
class RequiredDependencyField():
    """Validator of required when dependency field matches the condition
    """
    
    def __init__(self, field_name: str, value: bool|str|int, message: str = None):
        self.field_name = field_name
        self.match_value = value
        self.message = message
        
    def __call__(self, form, field, message=None):
        if self.field_name:
            if not hasattr(form, self.field_name):
                return 'The field:%s were does not exists in form' % (self.field_name)
            match_field = getattr(form, self.field_name)
            match_required = False
            if isinstance(self.match_value, bool):
                match_required = True if (self.match_value and match_field.data) else (True if ((not self.match_value) and (not match_field.data)) else False)
            elif isinstance(self.match_value, str):
                match_required = True if self.match_value == match_field.data else False
            elif isinstance(self.match_value, int):
                match_required = True if self.match_value == match_field.data else False
            
            if match_required:
                if not field.data:
                    return message if message else field.gettext('This field is required.')
            