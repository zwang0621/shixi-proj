package cache

import (
	"sync"
	"time"
)

type entry struct {
	val string
	exp time.Time
}

type MemoryCache struct {
	mu  sync.RWMutex
	m   map[string]entry
	ttl time.Duration
}

func NewMemory(ttl time.Duration) *MemoryCache {
	return &MemoryCache{m: make(map[string]entry), ttl: ttl}
}

func (c *MemoryCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return "", false
	}
	return e.val, true
}

func (c *MemoryCache) Set(key, val string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry{val: val, exp: time.Now().Add(c.ttl)}
}
