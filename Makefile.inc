DESTDIR = $(shell basename $(CURDIR))
INSTALL = install
PYTHON ?= python3
RCW = $(PYTHON) ../rcw.py

define rcw-rule
$1: $2
	$(RCW) -i $2 -o $1
endef

rcw_sources := $(wildcard */*.rcw)

# Maintain compatibility with byte_swap.tcl by creating a $(rcw).bin.swapped
# file if it contains the %littleendian64b=1 directive.
$(foreach rcw, $(rcw_sources), \
	$(eval suffix := $(shell gcc -E -x c -P -I . $(rcw) | \
		awk '/%littleendian64b=1/ { print ".swapped"; exit; }')) \
	$(eval bin := $(rcw:.rcw=.bin$(suffix))) \
	$(eval $(call rcw-rule, $(bin), $(rcw))) \
	$(eval targets := $(targets) $(bin)))

all: $(targets)

install: $(targets)
	$(INSTALL) -d $(DESTDIR)
	@for file in $^; do \
		$(INSTALL) -m 644 -D $$file $(DESTDIR)/$$file; \
	done
	$(INSTALL) -m 644 -D README $(DESTDIR)

clean:
	$(RM) -r $(targets)
	$(RM) -rf $(DESTDIR)
