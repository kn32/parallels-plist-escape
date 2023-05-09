#######################################################
# Copyright (C) 1999-2019 Parallels International GmbH.
# All Rights Reserved.
# http://www.parallels.com
#######################################################

KVER ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KVER)/build
DRIVER_DIR ?= $(PWD)
DRIVER_DATE ?= $(shell date +%Y%m%d)
DRIVER_MAJOR ?= 1
DRIVER_MINOR ?= 10
DRIVER_PATCH ?= 2
DRIVER_VERSION ?= $(DRIVER_MAJOR).$(DRIVER_MINOR).$(DRIVER_PATCH)
DRIVER := prl_tg

$(info 1: $(KERNEL_DIR))
$(info 2: $(DRIVER_DIR))
$(info 3: $(DRIVER_DATE))
$(info 4: $(DRIVER_VERSION))

export KERNEL_DIR
export DRIVER_DIR

CFILES = ./prltg.c ./prltg_call.c
HFILES = ./prltg_compat.h ./prltg_common.h ../Interfaces/prltg.h \
	../Interfaces/prltg_call.h ../../Interfaces/tgreq.h ../../../Interfaces/Tg.h

ccflags-y += -DDRV_SHORT_NAME=\"$(DRIVER)\"
ccflags-y += -DDRV_LONG_NAME="\"Parallels ToolGate\""
ccflags-y += -DDRV_DATE=\"$(DRIVER_DATE)\"
ccflags-y += -DDRV_VERSION=\"$(DRIVER_VERSION)\"
ccflags-y += -DDRV_MAJOR=$(DRIVER_MAJOR)
ccflags-y += -DDRV_MINOR=$(DRIVER_MINOR)
ccflags-y += -I$(obj)/../Interfaces
ccflags-y += -I$(obj)/../../../../../prl_vid/Video/Interfaces

obj-m += $(DRIVER).o
$(DRIVER)-objs += prltg.o prltg_call.o

prl_tg:	$(CFILES) $(HFILES)
	$(info Start compile $(DRIVER)...)
	$(MAKE) -C $(KERNEL_DIR) M=$(DRIVER_DIR) SRCROOT=$(DRIVER_DIR) CC=$(CC) modules

clean:
	$(info Start cleaning $(DRIVER)...)
	rm -rf *.o* *.ko *.mod* *symvers .tmp_versions .*.cmd *.ver modules.order
