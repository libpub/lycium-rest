#!/usr/bin/env python
# -*- coding: utf-8 -*-

class FormItemProps(object):
    """Properties for hidden scenario

    Args:
        object (_type_): _description_
    """
    
    def __init__(self, 
                 hide_in_table: bool = False, 
                 hide_in_form: bool = False,
                 hide_in_search: bool = False,
                 password: bool = False
                 ):
        self.hide_in_table = hide_in_table
        self.hide_in_form = hide_in_form
        self.hide_in_search = hide_in_search
        self.password = password

    def __call__(self, form, field):
        return True
    