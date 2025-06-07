package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockCache is a simple in-memory cache for testing
type MockCache struct {
	name        string
	cacheType   string
	items       map[string]*CacheItem
	mu          sync.RWMutex
	returnError bool
	stats       *CacheStats
}

// NewMockCache creates a new mock cache
func NewMockCache(name, cacheType string) *MockCache {
	return &MockCache{
		name:      name,
		cacheType: cacheType,
		items:     make(map[string]*CacheItem),
		stats: &CacheStats{
			Name: name,
			Type: cacheType,
		},
	}
}

// SetError makes the cache return errors for testing
func (m *MockCache) SetError(returnError bool) {
	m.returnError = returnError
}

// HasKey checks if a key exists (for testing)
func (m *MockCache) HasKey(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.items[key]
	return exists
}

// SetItem sets an item directly (for testing)
func (m *MockCache) SetItem(key string, item *CacheItem) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items[key] = item
}

// Get retrieves an item from the cache
func (m *MockCache) Get(ctx context.Context, key string) (*CacheItem, error) {
	if m.returnError {
		return nil, fmt.Errorf("mock error")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.items[key]
	if !exists {
		m.stats.Misses++
		return nil, ErrCacheMiss
	}

	// Check if expired
	if time.Now().After(item.ExpiresAt) {
		delete(m.items, key)
		m.stats.Misses++
		return nil, ErrCacheMiss
	}

	// Update access info
	item.AccessCount++
	item.LastAccess = time.Now()

	m.stats.Hits++
	return item, nil
}

// Set stores an item in the cache
func (m *MockCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	item := &CacheItem{
		Key:         key,
		Value:       value,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
		AccessCount: 0,
		LastAccess:  now,
		TTL:         ttl,
	}

	m.items[key] = item
	m.stats.Sets++
	m.stats.Size = int64(len(m.items))

	return nil
}

// Delete removes an item from the cache
func (m *MockCache) Delete(ctx context.Context, key string) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.items, key)
	m.stats.Deletes++
	m.stats.Size = int64(len(m.items))

	return nil
}

// Exists checks if a key exists in the cache
func (m *MockCache) Exists(ctx context.Context, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.items[key]
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(item.ExpiresAt) {
		return false
	}

	return true
}

// GetMulti retrieves multiple items
func (m *MockCache) GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error) {
	if m.returnError {
		return nil, fmt.Errorf("mock error")
	}

	result := make(map[string]*CacheItem)

	for _, key := range keys {
		if item, err := m.Get(ctx, key); err == nil {
			result[key] = item
		}
	}

	return result, nil
}

// SetMulti stores multiple items
func (m *MockCache) SetMulti(ctx context.Context, items map[string]*CacheItem) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	for key, item := range items {
		if err := m.Set(ctx, key, item.Value, item.TTL); err != nil {
			return err
		}
	}

	return nil
}

// DeleteMulti removes multiple items
func (m *MockCache) DeleteMulti(ctx context.Context, keys []string) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	for _, key := range keys {
		m.Delete(ctx, key)
	}

	return nil
}

// Increment increments a numeric value
func (m *MockCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	if m.returnError {
		return 0, fmt.Errorf("mock error")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.items[key]
	if !exists {
		// Create new item with delta value
		m.Set(ctx, key, delta, time.Hour)
		return delta, nil
	}

	// Convert value to int64
	var currentValue int64
	switch v := item.Value.(type) {
	case int64:
		currentValue = v
	case int:
		currentValue = int64(v)
	default:
		return 0, fmt.Errorf("value is not numeric")
	}

	newValue := currentValue + delta
	item.Value = newValue

	return newValue, nil
}

// Decrement decrements a numeric value
func (m *MockCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return m.Increment(ctx, key, -delta)
}

// Touch updates the TTL of an item
func (m *MockCache) Touch(ctx context.Context, key string, ttl time.Duration) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.items[key]
	if !exists {
		return ErrKeyNotFound
	}

	item.ExpiresAt = time.Now().Add(ttl)
	item.TTL = ttl

	return nil
}

// Clear removes all items from the cache
func (m *MockCache) Clear(ctx context.Context) error {
	if m.returnError {
		return fmt.Errorf("mock error")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]*CacheItem)
	m.stats.Size = 0

	return nil
}

// Flush is an alias for Clear
func (m *MockCache) Flush(ctx context.Context) error {
	return m.Clear(ctx)
}

// Stats returns cache statistics
func (m *MockCache) Stats(ctx context.Context) (*CacheStats, error) {
	if m.returnError {
		return nil, fmt.Errorf("mock error")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := *m.stats // Copy stats
	stats.Size = int64(len(m.items))

	if stats.Hits+stats.Misses > 0 {
		stats.HitRatio = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}

	return &stats, nil
}

// Type returns the cache type
func (m *MockCache) Type() string {
	return m.cacheType
}

// Name returns the cache name
func (m *MockCache) Name() string {
	return m.name
}
