obj-m += Question2.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
rm -rf *.o *.ko *.mod.* *.symvers *.order