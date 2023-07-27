# LINUX_KERN=/home/ishaan-vm-1804/Desktop/hpmmap-fix/obj/linux-basic
LINUX_KERN=/lib/modules/`uname -r`/build/

EXTRA_CFLAGS  += -DMODULE=1 -D__KERNEL__=1 -g

hpmmap-y := 	main.o \
		buddy.o \
		mm.o \
		mapper.o \
		mmap.o \
		override.o \
		probe.o \
		util-hashtable.o \
		hpmmap_syms.o \
		smapreg.o

hpmmap-objs := $(hpmmap-y)
obj-m := hpmmap.o


all:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_KERN) M=$(PWD) clean

