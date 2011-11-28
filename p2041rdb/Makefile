DESTDIR = .
INSTALL = install

rcw_sources := $(wildcard */*.txt)
targets = $(rcw_sources:.txt=.bin)

%.bin: %.txt
	sed '/^\#/d' $< | grep -v '^($)' | xxd -r > $@

all: $(targets)

install: $(targets)
	$(INSTALL) -d $(DESTDIR)
	@for file in $^; do \
		$(INSTALL) -m 644 -D $$file $(DESTDIR)/$$file; \
	done
	$(INSTALL) -m 644 -D README $(DESTDIR)

clean:
	$(RM) -r $(targets)
