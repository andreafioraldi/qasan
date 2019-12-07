# -*-Makefile-*-

LIBSTB_DIR = libstb

SUBDIRS += $(LIBSTB_DIR)

LIBSTB_SRCS = container.c rom.c tpm_chip.c stb.c
LIBSTB_OBJS = $(LIBSTB_SRCS:%.c=%.o)
LIBSTB = $(LIBSTB_DIR)/built-in.o

include $(SRC)/$(LIBSTB_DIR)/drivers/Makefile.inc
include $(SRC)/$(LIBSTB_DIR)/tss/Makefile.inc

$(LIBSTB): $(LIBSTB_OBJS:%=$(LIBSTB_DIR)/%) $(DRIVERS) $(TSS)

libstb/create-container: libstb/create-container.c
	$(call Q, HOSTCC ,$(HOSTCC) $(HOSTCFLAGS) \
	-Wpadded -O0 -g -I$(SRC) -I$(SRC)/include -o $@ $< -lssl -lcrypto,$<)

clean: create-container-clean

create-container-clean:
	$(RM) libstb/create-container
