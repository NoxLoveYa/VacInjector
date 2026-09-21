// VacSafe driver placeholder (Phase 06, only if Phase 02 go-decision == yes).
// IOCTLs: READ/WRITE via MmCopyVirtualMemory, HIDE assist. Test-sign lab VM only.
#define VACSAFE_IOCTL_READ 0x80002000
#define VACSAFE_IOCTL_WRITE 0x80002004
#define VACSAFE_IOCTL_HIDE 0x80002008
