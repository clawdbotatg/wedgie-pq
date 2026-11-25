# Build: make MPY_DIR=/path/to/micropython-v1.29.0 CFLAGS_EXTRA="-I../p2/stubs -ffreestanding -O2"
# (needs arm-none-eabi-gcc and pyelftools)
MPY_DIR ?= ../../../micropython
MOD = slh
SRC = slh.c
ARCH = armv6m
LINK_RUNTIME = 1
include $(MPY_DIR)/py/dynruntime.mk
