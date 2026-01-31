# Definition of the module object file
obj-m += bpf_blinder.o

# Default target: builds the kernel module using the kernel build system
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Clean target: removes generated build files and binaries
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean