#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} buffer SEC(".maps");

static inline void log_process_name(const struct linux_binprm *bprm, umode_t mode)
{
	struct event *event = bpf_ringbuf_reserve(&buffer, sizeof(struct event), 0);

	if (event) {
		event->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
		bpf_probe_read_str(&event->filename, sizeof(event->filename),
				   bprm->filename);
		event->mode = mode;
		bpf_ringbuf_submit(event, 0);
	}
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec_ro, struct linux_binprm *bprm)
{
	umode_t mode = bprm->file->f_inode->i_mode;
	if (((mode & 0003) == 0003)
	 || ((mode & 0030) == 0030)
	 || ((mode & 0300) == 0300)) {
		log_process_name(bprm, mode & 0777);
		return -EACCES;
	}

	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
