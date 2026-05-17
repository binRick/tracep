//go:build !linux

package dnstrace

// pidForUDPPort has no portable implementation off Linux: there is no
// /proc socket→inode→pid table. DNS queries are still captured and shown,
// just without process attribution (pid 0, name "?").
func pidForUDPPort(port uint16) (int, string) { return 0, "?" }
