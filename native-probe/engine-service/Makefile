obj-m += gxfp51b7_engine_service.o
KDIR ?= /usr/lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) W=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
