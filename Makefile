TOPTARGETS := all install clean

SUBDIRS := src share

DESTDIR := /usr/local
export DESTDIR

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)
