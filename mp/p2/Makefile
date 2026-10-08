# Build: make MPY_DIR=/path/to/micropython-v1.29.0   (needs arm-none-eabi-gcc and pyelftools)
MPY_DIR ?= ../../../micropython
MOD = p2
SRC = p2.c
ARCH = armv6m
LINK_RUNTIME = 1
include $(MPY_DIR)/py/dynruntime.mk
