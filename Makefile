# contrib/pg_auth_mon/Makefile

MODULES = pg_auth_mon
OBJS = pg_auth_mon.o
PGFILEDESC = "pg_auth_mon - record authentication attempts"

EXTENSION = pg_auth_mon
DATA = pg_auth_mon--1.0.sql

REGRESS = pg_auth_mon

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
