# -*-Makefile-*-

DRIVERS_DIR = libstb/drivers

SUBDIRS += $(DRIVERS_DIR)

DRIVERS_SRCS = romcode.c tpm_i2c_interface.c tpm_i2c_nuvoton.c sw_driver.c sha512.c
DRIVERS_OBJS = $(DRIVERS_SRCS:%.c=%.o)
DRIVERS = $(DRIVERS_DIR)/built-in.o

$(DRIVERS): $(DRIVERS_OBJS:%=$(DRIVERS_DIR)/%)
