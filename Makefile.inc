DESTDIR = .
INSTALL = install
PYTHON ?= python2
RCW = $(PYTHON) ../rcw.py
QSPI_SWAP_LIST = $(shell pwd)/../qspi_swap_list.txt
QSPI_SWAP_SCRIPT=$(shell pwd)/../qspi_swap.sh

rcw_sources := $(wildcard */*.rcw)
txt_sources := $(wildcard */*.txt)
swap_sources := $(wildcard */*.swapped)
targets = $(txt_sources:.txt=.bin) $(rcw_sources:.rcw=.bin) $(swap_sources)

%.bin: %.txt
	sed '/^\#/d' $< | grep -v '^($)' | xxd -r > $@

%.bin: %.rcw
	$(RCW) -i $< -o $@

all: $(targets)
	$(QSPI_SWAP_SCRIPT) $(QSPI_SWAP_LIST)

install: $(targets)
	$(INSTALL) -d $(DESTDIR)
	@for file in $^; do \
		$(INSTALL) -m 644 -D $$file $(DESTDIR)/$$file; \
	done
	$(INSTALL) -m 644 -D README $(DESTDIR)

clean:
	$(RM) -r $(targets)
	$(RM) -rf $(DESTDIR)/*
