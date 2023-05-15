#LINUX_KERN=/usr/src/kernels/$(shell uname -r)
LINUX_KERN=/lib/modules/`uname -r`/build/

EXTRA_CFLAGS  += -DMODULE=1 -D__KERNEL__=1

hpmmaptest-y := test.o

hpmmaptest-objs := $(hpmmaptest-y)
obj-m := hpmmaptest.o


all:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) clean

