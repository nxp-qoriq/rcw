DESTDIR = .
BOARDS = b4420qds b4860qds \
	 p2041rdb p3041ds p4080ds p5020ds p5040ds \
	 t1040rdb t1042rdb_pi t1040qds t2080rdb t2080qds t2081qds t4240qds t4240rdb

VER = $(shell git describe --tags)

all install clean:
	@for board in $(BOARDS); do \
		$(MAKE) -C $$board $@ DESTDIR=$(DESTDIR)/$$board; \
	done

release: $(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz)

$(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz): rcw-%-$(VER).tar.gz:
	git archive --format=tar HEAD --prefix rcw- $* | gzip -9 > $@

.PHONY: all install clean release $(foreach board,$(BOARDS),rcw-$(board)-$(VER).tar.gz)
