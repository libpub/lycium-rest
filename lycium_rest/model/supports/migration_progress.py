#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, String

from hawthorn.modelutils import ModelBase
from hawthorn.modelutils.behaviors import ModifyingBehevior

class _MigrationProgressTable(ModelBase):
    __tablename__ = 'sys_migration_progress'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    app = Column('app', String(64), index=True)
    version = Column('version', String(64), index=True)
    module = Column('module', String(64), index=True)
    value = Column('value', String(256))
    progress = Column('progress', Integer)
    total = Column('total', Integer)
    cost_seconds = Column('cost_seconds', Integer)
    left_seconds = Column('left_seconds', Integer)

class MigrationProgress(_MigrationProgressTable, ModifyingBehevior):
    """
    Migration module progress
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

