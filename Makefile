# SPDX-License-Identifier: BSD-3-Clause
#
# Makefile for caam-keygen application
#
OBJS = caam-keygen.o

TARGET = caam-keygen

KEYBLOB_LOCATION ?= /data/caam/

CFLAGS += -O2
CFLAGS += -DKEYBLOB_LOCATION="\"$(KEYBLOB_LOCATION)\""

PREFIX ?= /usr

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

.PHONY: install
install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)
