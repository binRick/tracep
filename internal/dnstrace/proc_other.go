//go:build !linux && !darwin

package dnstrace

// pidForUDPPort has no portable implementation on this OS: there is no
// /proc socket→inode→pid table and no equivalent of lsof we know about.
// DNS queries are still captured and shown, just without process
// attribution (pid 0, name "?"). Linux uses proc_linux.go; darwin uses
// proc_darwin.go (lsof-backed).
func pidForUDPPort(port uint16) (int, string) { return 0, "?" }
