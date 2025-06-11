package caches

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// cacheItem represents an item in the cache with TTL
type cacheItem struct {
	value  interface{}
	expiry time.Time
}

// MemoryCache implements an in-memory cache with LRU eviction
type MemoryCache struct {
	name    string
	lruCache *lru.Cache[string, *cacheItem]
	maxSize int
	mu      sync.RWMutex
}

// NewMemory creates a new in-memory cache
func NewMemory(name string, maxSize int) *MemoryCache {
	cache, _ := lru.New[string, *cacheItem](maxSize)
	return &MemoryCache{
		name:     name,
		lruCache: cache,
		maxSize:  maxSize,
	}
}

func (mc *MemoryCache) Name() string {
	return mc.name
}

func (mc *MemoryCache) Get(key string) (interface{}, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	item, exists := mc.lruCache.Get(key)
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	// Check TTL
	if !item.expiry.IsZero() && time.Now().After(item.expiry) {
		mc.mu.RUnlock()
		mc.mu.Lock()
		mc.lruCache.Remove(key)
		mc.mu.Unlock()
		mc.mu.RLock()
		return nil, fmt.Errorf("key expired")
	}

	return item.value, nil
}

func (mc *MemoryCache) Set(key string, value interface{}, ttl time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	item := &cacheItem{
		value: value,
	}

	// Set expiry if TTL is provided
	if ttl > 0 {
		item.expiry = time.Now().Add(ttl)
	}

	// LRU cache handles eviction automatically
	mc.lruCache.Add(key, item)
	return nil
}

func (mc *MemoryCache) Delete(key string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.lruCache.Remove(key)
	return nil
}

func (mc *MemoryCache) Clear() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.lruCache.Purge()
	return nil
}

func (mc *MemoryCache) Close() error {
	return mc.Clear()
}
