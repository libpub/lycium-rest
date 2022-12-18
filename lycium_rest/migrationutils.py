#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import traceback
import logging
from hawthorn.dbproxy import DbProxy
from hawthorn.modelutils import meta_data
from .model.supports import Migration, MigrationProgress

APP_NAME = 'Unknown'
MIGRATES = []
LOG = logging.getLogger('migrations.main')

if os.getenv('APP_NAME'):
    APP_NAME = os.getenv('APP_NAME', 'Unknown')

def set_appname(appname=''):
    global APP_NAME
    if appname and isinstance(appname, str):
        APP_NAME = appname

def set_migrates(migrates=[]):
    global MIGRATES
    if migrates and isinstance(migrates, list):
        MIGRATES = migrates

async def create_tables():
    # ensure table were created
    dbinstance = DbProxy().get_model_dbinstance(Migration)
    async with dbinstance.engine.begin() as conn:
        await conn.run_sync(meta_data.create_all)
        LOG.info('ensure all table meta data were created')
        # meta_data.create_all(conn.sync_connection)

async def do_migrations():
    await create_tables()
    for fn in MIGRATES:
        version = migration_parse_version(fn.__name__)
        if not version:
            continue
        cur_migration_executed = await migration_check_version(version)
        if cur_migration_executed:
            continue
        migration_result = await fn()
        if migration_result is not False:
            await migration_finish_version(version)
            LOG.info('migrates by version:%s finished.' % (version))

async def migration_check_version(version):
    obj = await DbProxy().find_item(Migration, {Migration.version==version})
    if obj and obj.status > 0:
        return True
    return False

async def migration_finish_version(version):
    obj = await DbProxy().find_item(Migration, {Migration.app==APP_NAME, Migration.version==version})
    if not obj:
        obj = Migration()
        obj.set_session_uid(APP_NAME)
        obj.app = APP_NAME
        obj.version = version
    else:
        obj.set_session_uid(APP_NAME)
        obj.obsoleted = 0
    obj.status = 1
    if obj.id:
        await DbProxy().update_item(obj, auto_flush=True)
    else:
        await DbProxy().insert_item(obj, auto_flush=True)
    return True

def migration_parse_version(fnName):
    slices = fnName.split('_')
    if len(slices) < 1:
        return ''
    return slices[1]

async def migration_get_progress(module, total_cb=None):
    tb = traceback.extract_stack()
    version = migration_parse_version(tb[-2][2])

    p = await DbProxy().find_item(MigrationProgress, {MigrationProgress.app==APP_NAME, MigrationProgress.version==version, MigrationProgress.module==module})
    if not p:
        p = MigrationProgress()
        p.set_session_uid(APP_NAME)
        p.app = APP_NAME
        p.version = version
        p.progress = 0
        p.module = module
        p.value = ''
        p.total = total_cb() if total_cb else 0
        p.cost_seconds = 0
        p.left_seconds = 0
        await DbProxy().insert_item(p, auto_flush=True)
    else:
        p.set_session_uid(APP_NAME)
    
    return p

async def migration_update_progress(progressRecord, curProcessed, value, dt):
    progressRecord.progress += curProcessed
    progressRecord.value = str(value)
    progressRecord.cost_seconds += int(dt)
    speed = float(progressRecord.progress / progressRecord.cost_seconds) if progressRecord.cost_seconds else 1.0
    progressRecord.left_seconds = int((progressRecord.total - progressRecord.progress) / speed)
    await DbProxy().update_item(progressRecord)
    return progressRecord
