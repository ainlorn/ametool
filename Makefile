CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
PREFIX  ?= /usr
BINDIR  ?= $(PREFIX)/bin

.PHONY: all clean install

all: ametool

ametool: ametool.c
	$(CC) $(CFLAGS) -o $@ $<

install: ametool
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 ametool $(DESTDIR)$(BINDIR)/ametool

clean:
	rm -f ametool
