package caches

import (
	"fmt"
	"sync"
	"time"
)

// MemoryCache implements an in-memory cache
type MemoryCache struct {
	name    string
	data    sync.Map
	ttlMap  sync.Map
	maxSize int
	size    int64
	mu      sync.RWMutex
}

// NewMemory creates a new in-memory cache
func NewMemory(name string, maxSize int) *MemoryCache {
	return &MemoryCache{
		name:    name,
		maxSize: maxSize,
	}
}

func (mc *MemoryCache) Name() string {
	return mc.name
}

func (mc *MemoryCache) Get(key string) (interface{}, error) {
	// Check TTL
	if ttlInterface, exists := mc.ttlMap.Load(key); exists {
		if ttl, ok := ttlInterface.(time.Time); ok && time.Now().After(ttl) {
			mc.Delete(key)
			return nil, fmt.Errorf("key expired")
		}
	}
	
	value, exists := mc.data.Load(key)
	if !exists {
		return nil, fmt.Errorf("key not found")
	}
	
	return value, nil
}

func (mc *MemoryCache) Set(key string, value interface{}, ttl time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	// Simple size check (not exact)
	if mc.size >= int64(mc.maxSize) {
		return fmt.Errorf("cache full")
	}
	
	mc.data.Store(key, value)
	if ttl > 0 {
		mc.ttlMap.Store(key, time.Now().Add(ttl))
	}
	mc.size++
	
	return nil
}

func (mc *MemoryCache) Delete(key string) error {
	mc.data.Delete(key)
	mc.ttlMap.Delete(key)
	
	mc.mu.Lock()
	mc.size--
	mc.mu.Unlock()
	
	return nil
}

func (mc *MemoryCache) Clear() error {
	mc.data = sync.Map{}
	mc.ttlMap = sync.Map{}
	
	mc.mu.Lock()
	mc.size = 0
	mc.mu.Unlock()
	
	return nil
}

func (mc *MemoryCache) Close() error {
	return mc.Clear()
}