#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hawthorn.asynchttphandler import GeneralTornadoHandler

SESSION_UID_KEY = 'uid'

def authorized_session_access_control(handler: GeneralTornadoHandler):
    ac_result = False
    ac_message = 'Reject'
    authed_uid = None
    if handler.session:
        authed_uid = handler.session[SESSION_UID_KEY]
    if authed_uid:
        ac_result = True
        ac_message = 'Authorized'
    
    return ac_result, ac_message
