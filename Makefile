# contrib/pg_auth_mon/Makefile

MODULE_big = pg_auth_mon
OBJS = pg_auth_mon.o
PGFILEDESC = "pg_auth_mon - record authentication attempts"
ifdef ENABLE_GCOV
	PG_CPPFLAGS += -g -ggdb -pg -O0 -fprofile-arcs -ftest-coverage
endif
EXTENSION = pg_auth_mon
DATA = pg_auth_mon--1.0.sql pg_auth_mon--1.0--1.1.sql

REGRESS = pg_auth_mon

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
ifdef ENABLE_GCOV
	SHLIB_LINK  += -lgcov --coverage
endif
