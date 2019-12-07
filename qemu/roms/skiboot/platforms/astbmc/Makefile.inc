SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = pnor.o common.o slots.o \
	      palmetto.o habanero.o firestone.o \
	      p8dtu.o p8dnu.o \
	      garrison.o barreleye.o \
	      witherspoon.o zaius.o romulus.o p9dsu.o

ASTBMC = $(PLATDIR)/astbmc/built-in.o
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)

