# contrib/pg_auth_mon/Makefile

MODULES = pg_auth_mon
OBJS = pg_auth_mon.o
PG_CPPFLAGS = --std=c99

ifdef ENABLE_GCOV
	PG_CPPFLAGS += -g -ggdb -pg -O0 -fprofile-arcs -ftest-coverage
endif

PGFILEDESC = "pg_auth_mon - record authentication attempts"

EXTENSION = pg_auth_mon
DATA = pg_auth_mon--1.0.sql

REGRESS = pg_auth_mon

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

SHLIB_LINK += -levent -levent_pthreads -pthread
ifdef ENABLE_GCOV
	PG_CPPFLAGS += --coverage
	SHLIB_LINK  += -lgcov --coverage
	EXTRA_CLEAN += *.gcno
endif
