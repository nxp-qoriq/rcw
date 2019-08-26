DESTDIR = $(shell basename $(CURDIR))
INSTALL = install
PYTHON ?= python3
RCW = $(PYTHON) ../rcw.py
PREPROCESSOR := gcc -E -x c -P -I .
.DEFAULT_GOAL := all

define rcw-rule
$1: $2
	$(RCW) -i $2 -o $1
endef

# Creates a temporary unswapped RCW source code variant based on a swapped one
# (containing the %littleendian64b=1 directive)
# TODO: make this rule track changes in all files #included from $2.
define unswapped-rcw-rule
$1: $2
	$(PREPROCESSOR) $2 | sed -e 's|%littleendian64b=1||g' > $1
endef

rcw_sources := $(wildcard */*.rcw)

# Maintain compatibility with byte_swap.tcl by creating a $(rcw).bin.swapped
# file if it contains the %littleendian64b=1 directive.
$(foreach rcw, $(rcw_sources), \
	$(eval suffix := $(shell $(PREPROCESSOR) $(rcw) | \
		awk '/%littleendian64b=1/ { print ".swapped"; exit; }')) \
	$(eval bin := $(rcw:.rcw=.bin$(suffix))) \
	$(eval $(call rcw-rule, $(bin), $(rcw))) \
	$(eval targets := $(targets) $(bin)))

# Also maintain compatibility with users of unswapped binaries when swapped
# versions are available (e.g. tfa). For each swapped binary, generate the
# unswapped variant as well.
$(foreach swapped_bin, $(filter %.bin.swapped, $(targets)), \
	$(eval rcw := $(patsubst %.bin.swapped, %.rcw, $(swapped_bin))) \
	$(eval unswapped_rcw := $(join $(dir $(rcw)), .$(notdir $(rcw)).unswapped)) \
	$(eval $(call unswapped-rcw-rule, $(unswapped_rcw), $(rcw))) \
	$(eval unswapped_bin := $(patsubst %.bin.swapped, %.bin, $(swapped_bin))) \
	$(eval $(call rcw-rule, $(unswapped_bin), $(unswapped_rcw))) \
	$(eval tmpfiles := $(tmpfiles) $(unswapped_rcw)) \
	$(eval targets := $(targets) $(unswapped_bin)))

all: $(targets)

install: $(targets)
	$(INSTALL) -d $(DESTDIR)
	@for file in $^; do \
		$(INSTALL) -m 644 -D $$file $(DESTDIR)/$$file; \
	done
	$(INSTALL) -m 644 -D README $(DESTDIR)

clean:
	$(RM) $(tmpfiles)
	$(RM) -r $(targets)
	$(RM) -rf $(DESTDIR)
