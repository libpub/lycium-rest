#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, BigInteger, SmallInteger, String

from hawthorn.modelutils import ModelBase
from hawthorn.modelutils.behaviors import ModifyingBehevior

class _MigrationTable(ModelBase):
    __tablename__ = 'sys_migration'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    app = Column('app', String(64), index=True)
    version = Column('version', String(64), index=True)
    status = Column('status', SmallInteger, index=True)

class Migration(_MigrationTable, ModifyingBehevior):
    """
    Migration information
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
