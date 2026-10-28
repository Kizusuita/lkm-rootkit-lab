# Makefiles are processed by the make tool, this isn't C!
# Below tells kernel build system to compile rootkit.c into a loadable module (.ko), m = module
obj-m += rootkit.o

# Adds /include folders to compiler's search path.
ccflags-y := -I$(src)/include

# DEFAULT TARGET
all:
	# Jumps into kernel build dir, it knows how to compile modules correctly
	# M=$(PWD) modules tells the compiler to come back to this directory to build
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# REMOVES BUILD ARTIFACTS
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

