default: load_check_exec_ro_lsm

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

check_exec_ro_lsm.o: vmlinux.h check_exec_ro_lsm.c
	clang -g -O2 -c -target bpf check_exec_ro_lsm.c -o $@

check_exec_ro_lsm.h: check_exec_ro_lsm.o
	bpftool gen skeleton $< > $@

load_check_exec_ro_lsm: check_exec_ro_lsm.h load_check_exec_ro_lsm.c
	clang -lbpf $@.c -o $@

install: load_check_exec_ro_lsm
	install load_check_exec_ro_lsm ${DESTDIR}/sbin/load_check_exec_ro_lsm

clean:
	rm -f load_check_exec_ro_lsm check_exec_ro_lsm.h check_exec_ro_lsm.o vmlinux.h
