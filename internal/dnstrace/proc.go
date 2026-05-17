package dnstrace

import (
	"sync"
	"time"
)

// pidForUDPPort is implemented per-platform (proc_linux.go / proc_other.go):
// on Linux it resolves the owning PID via /proc; elsewhere it is a no-op
// returning (0, "?") since there is no portable socket→PID mapping.

// procCache caches the (srcPort → pid, processName) mapping with a short TTL
// to avoid hammering /proc on every packet.
type procCache struct {
	mu      sync.Mutex
	entries map[uint16]*cacheEntry
}

type cacheEntry struct {
	pid   int
	name  string
	born  time.Time
}

const ttl = 2 * time.Second

func newProcCache() *procCache {
	return &procCache{entries: make(map[uint16]*cacheEntry)}
}

// lookup returns the PID and process name for the process that has a UDP socket
// bound to the given local port. Returns (0, "?") if not found.
func (c *procCache) lookup(port uint16) (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[port]; ok && time.Since(e.born) < ttl {
		return e.pid, e.name
	}

	pid, name := pidForUDPPort(port)
	c.entries[port] = &cacheEntry{pid: pid, name: name, born: time.Now()}

	// Periodically sweep expired entries to avoid unbounded growth.
	if len(c.entries) > 1024 {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.born) > ttl*4 {
				delete(c.entries, k)
			}
		}
	}
	return pid, name
}
