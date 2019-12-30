DESTDIR = .
BOARDS = b4420qds b4860qds \
	 ls1012ardb ls1012a2g5rdb ls1012afrdm ls1012afrwy ls1012aqds \
	 ls1021aqds ls1021atwr ls1021atsn \
	 ls1043aqds ls1043ardb \
	 ls1046ardb ls1046aqds ls1046afrwy \
	 ls1088ardb ls1088aqds\
	 ls1028ardb ls1028aqds\
	 ls2088ardb ls2088ardb_rev1.1 ls2088aqds \
	 lx2160ardb lx2160aqds lx2160ardb_rev2 lx2160aqds_rev2 \
	 p2041rdb p3041ds p4080ds p5020ds p5040ds \
	 t1024qds t1023rdb t1024rdb t1040rdb t1042rdb t1042rdb_pi t1040qds \
	 t2080rdb t2080qds t2081qds t4240qds t4240rdb t1040d4rdb t1042d4rdb

TCLSH := $(shell command -v tclsh 2> /dev/null)

VER = $(shell git describe --tags)

all install clean:
ifndef TCLSH
	$(error "tclsh is not available. please  install it.")
	exit 1
endif
	@for board in $(BOARDS); do \
		$(MAKE) -C $$board $@ DESTDIR=$(DESTDIR)/$$board; \
	done

release: $(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz)

$(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz): rcw-%-$(VER).tar.gz:
	git archive --format=tar HEAD --prefix rcw- $* | gzip -9 > $@

.PHONY: all install clean release $(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz)
