# LSM BPF - exec only readonly binaries

## How to build

```
# On Ubuntu
$ sudo apt-get install libc6-dev-i386 libbpf0 libbpf-dev

# On Fedora 35
$ sudo dnf install clang bpftool libbpf-devel glibc-devel.i686 glibc-devel.x86_64

$ make
```

## How to install

Run:
```
$ sudo make DESTDIR=/usr install
# will execute following commands
# sudo cp src/load_check_exec_ro_lsm /usr/sbin
# sudo cp share/check_exec_ro_lsm.service /etc/systemd/system/

# After that you can enable the service with
$ sudo systemctl daemon-reload
$ sudo systemctl enable check_exec_ro_lsm.service
$ sudo systemctl start check_exec_ro_lsm.service
```
