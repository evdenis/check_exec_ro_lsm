default:

clean:
	rm -f check_exec_ro_lsm.service

install:
	sed -e 's!DESTDIR!${DESTDIR}!' check_exec_ro_lsm.service.tmpl > check_exec_ro_lsm.service
	install --mode=0644 check_exec_ro_lsm.service /etc/systemd/system/
