DESTDIR = .
INSTALL = install
PYTHON ?= python2
RCW = $(PYTHON) ../rcw.py

rcw_sources := $(wildcard */*.rcw)
txt_sources := $(wildcard */*.txt)
targets = $(txt_sources:.txt=.bin) $(rcw_sources:.rcw=.bin)

%.bin: %.txt
	sed '/^\#/d' $< | grep -v '^($)' | xxd -r > $@

%.bin: %.rcw
	$(RCW) -i $< -o $@

all: $(targets)

install: $(targets)
	$(INSTALL) -d $(DESTDIR)
	@for file in $^; do \
		$(INSTALL) -m 644 -D $$file $(DESTDIR)/$$file; \
	done
	$(INSTALL) -m 644 -D README $(DESTDIR)

clean:
	$(RM) -r $(targets)
