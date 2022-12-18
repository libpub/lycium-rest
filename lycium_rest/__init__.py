#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import locale
import i18n
import logging

LOG = logging.getLogger('hawthorn')
default_language, _ = locale.getdefaultlocale()

i18n.set('fallback', 'en_US')

def init_i18n_locales_path():
    lan_path = os.path.join(os.path.dirname(__file__), 'locales')
    LOG.info("Initialize i18n language locales path %s", lan_path)
    if not os.path.exists(lan_path):
        # lan_path = os.path.join(os.path.dirname(__file__), 'locales')
        # TODO: process if this deployment environment occured
        pass
    if os.path.exists(lan_path):
        LOG.info("add language locales path: %s", lan_path)
        i18n.load_path.append(lan_path)

def init_i18n(language: str = None):
    LOG.info("Initialize i18n configuration")
    if not language:
        language = default_language
    i18n.set('locale', language)
    i18n.set('fallback', 'en_US')

init_i18n()
init_i18n_locales_path()
