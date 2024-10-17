CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = main.o ../dh_keys.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include

LDADD += -lteec -L$(TEEC_EXPORT)/lib

BINARY = dh_with_derive

.PHONY: all clean

all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

../dh_keys.o: ../dh_keys.c ../dh_keys.h
	$(CC) $(CFLAGS) -c ../dh_keys.c -o ../dh_keys.o
