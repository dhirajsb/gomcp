package cache

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"go.opentelemetry.io/otel/trace"

	"github.com/dhirajsb/gomcp/internal/telemetry"
)

// MemoryCache implements an in-memory cache with LRU eviction
type MemoryCache struct {
	name      string
	config    CacheConfig
	items     map[string]*memoryCacheItem
	lruList   *lruList
	mu        sync.RWMutex
	stats     *CacheStats
	ticker    *time.Ticker
	stopCh    chan struct{}
	startTime time.Time
	tracer    trace.Tracer
}

type memoryCacheItem struct {
	item    *CacheItem
	lruNode *lruNode
	size    int64
}

// LRU list implementation
type lruList struct {
	head *lruNode
	tail *lruNode
	size int
}

type lruNode struct {
	key  string
	prev *lruNode
	next *lruNode
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(name string, config CacheConfig) *MemoryCache {
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 1 * time.Hour
	}
	if config.MaxSize == 0 {
		config.MaxSize = 10000 // Default max items
	}
	if config.MaxMemory == 0 {
		config.MaxMemory = 100 * 1024 * 1024 // 100MB default
	}

	mc := &MemoryCache{
		name:    name,
		config:  config,
		items:   make(map[string]*memoryCacheItem),
		lruList: newLRUList(),
		stats: &CacheStats{
			Name: name,
			Type: "memory",
		},
		stopCh:    make(chan struct{}),
		startTime: time.Now(),
	}

	// Start cleanup goroutine
	mc.ticker = time.NewTicker(1 * time.Minute)
	go mc.cleanupExpired()

	return mc
}

// SetTracer sets the OpenTelemetry tracer for distributed tracing
func (mc *MemoryCache) SetTracer(tracer trace.Tracer) {
	mc.tracer = tracer
}

// newLRUList creates a new LRU list
func newLRUList() *lruList {
	head := &lruNode{}
	tail := &lruNode{}
	head.next = tail
	tail.prev = head

	return &lruList{
		head: head,
		tail: tail,
		size: 0,
	}
}

// Get retrieves an item from the cache
func (mc *MemoryCache) Get(ctx context.Context, key string) (*CacheItem, error) {
	// Start distributed tracing span
	var span trace.Span
	if mc.tracer != nil {
		ctx, span = telemetry.StartSpan(ctx, mc.tracer, "cache.get",
			telemetry.NewSpanAttributeBuilder().
				Component("cache").
				Operation("get").
				String("cache.name", mc.name).
				String("cache.type", "memory").
				Cache(false, key). // Will update hit status later
				Build()...)
		defer span.End()
	}

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	mc.stats.LastAccess = time.Now()

	item, exists := mc.items[key]
	if !exists {
		mc.stats.Misses++
		if span != nil {
			telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
				Bool("cache.hit", false).
				String("cache.miss_reason", "key_not_found").
				Build()...)
			telemetry.AddEvent(span, "cache.miss")
			telemetry.RecordSuccess(span)
		}
		return nil, ErrCacheMiss
	}

	// Check if expired
	if time.Now().After(item.item.ExpiresAt) {
		mc.stats.Misses++
		go mc.deleteExpired(key) // Clean up asynchronously
		if span != nil {
			telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
				Bool("cache.hit", false).
				String("cache.miss_reason", "expired").
				Build()...)
			telemetry.AddEvent(span, "cache.miss.expired")
			telemetry.RecordSuccess(span)
		}
		return nil, ErrCacheMiss
	}

	// Update access info
	item.item.AccessCount++
	item.item.LastAccess = time.Now()

	// Move to front of LRU list
	mc.lruList.moveToFront(item.lruNode)

	mc.stats.Hits++

	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			Bool("cache.hit", true).
			Int64("cache.access_count", item.item.AccessCount).
			Int64("cache.size_bytes", item.size).
			Build()...)
		telemetry.AddEvent(span, "cache.hit")
		telemetry.RecordSuccess(span)
	}

	return item.item, nil
}

// Set stores an item in the cache
func (mc *MemoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	// Start distributed tracing span
	var span trace.Span
	if mc.tracer != nil {
		ctx, span = telemetry.StartSpan(ctx, mc.tracer, "cache.set",
			telemetry.NewSpanAttributeBuilder().
				Component("cache").
				Operation("set").
				String("cache.name", mc.name).
				String("cache.type", "memory").
				String("cache.key", key).
				Build()...)
		defer span.End()
	}

	if ttl == 0 {
		ttl = mc.config.DefaultTTL
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Calculate item size
	size := mc.calculateSize(value)
	isUpdate := false
	evictionsPerformed := 0

	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			Int64("cache.item_size_bytes", size).
			String("cache.ttl", ttl.String()).
			Build()...)
	}

	// Check if this is an update
	if _, exists := mc.items[key]; exists {
		isUpdate = true
	}

	// Check memory limits
	if mc.config.MaxMemory > 0 && mc.stats.Memory+size > mc.config.MaxMemory {
		evictionsPerformed += mc.evictLRU(size)
		if span != nil {
			telemetry.AddEvent(span, "cache.eviction.memory_limit")
		}
	}

	// Check size limits
	if mc.config.MaxSize > 0 && int64(len(mc.items)) >= mc.config.MaxSize {
		evictionsPerformed += mc.evictLRU(0)
		if span != nil {
			telemetry.AddEvent(span, "cache.eviction.size_limit")
		}
	}

	now := time.Now()
	cacheItem := &CacheItem{
		Key:         key,
		Value:       value,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
		AccessCount: 0,
		LastAccess:  now,
		TTL:         ttl,
	}

	// Remove existing item if present
	if existingItem, exists := mc.items[key]; exists {
		mc.stats.Memory -= existingItem.size
		mc.lruList.remove(existingItem.lruNode)
	}

	// Add new item
	lruNode := mc.lruList.addToFront(key)
	mc.items[key] = &memoryCacheItem{
		item:    cacheItem,
		lruNode: lruNode,
		size:    size,
	}

	mc.stats.Memory += size
	mc.stats.Sets++
	mc.stats.Size = int64(len(mc.items))

	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			Bool("cache.is_update", isUpdate).
			Int("cache.evictions_performed", evictionsPerformed).
			Int64("cache.total_memory_bytes", mc.stats.Memory).
			Int64("cache.total_items", mc.stats.Size).
			Build()...)

		if isUpdate {
			telemetry.AddEvent(span, "cache.item.updated")
		} else {
			telemetry.AddEvent(span, "cache.item.created")
		}
		telemetry.RecordSuccess(span)
	}

	return nil
}

// Delete removes an item from the cache
func (mc *MemoryCache) Delete(ctx context.Context, key string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if item, exists := mc.items[key]; exists {
		mc.stats.Memory -= item.size
		mc.lruList.remove(item.lruNode)
		delete(mc.items, key)
		mc.stats.Deletes++
		mc.stats.Size = int64(len(mc.items))
	}

	return nil
}

// Exists checks if a key exists in the cache
func (mc *MemoryCache) Exists(ctx context.Context, key string) bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	item, exists := mc.items[key]
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(item.item.ExpiresAt) {
		go mc.deleteExpired(key)
		return false
	}

	return true
}

// GetMulti retrieves multiple items
func (mc *MemoryCache) GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error) {
	result := make(map[string]*CacheItem)

	for _, key := range keys {
		if item, err := mc.Get(ctx, key); err == nil {
			result[key] = item
		}
	}

	return result, nil
}

// SetMulti stores multiple items
func (mc *MemoryCache) SetMulti(ctx context.Context, items map[string]*CacheItem) error {
	for key, item := range items {
		if err := mc.Set(ctx, key, item.Value, item.TTL); err != nil {
			return err
		}
	}
	return nil
}

// DeleteMulti removes multiple items
func (mc *MemoryCache) DeleteMulti(ctx context.Context, keys []string) error {
	for _, key := range keys {
		mc.Delete(ctx, key)
	}
	return nil
}

// Increment increments a numeric value
func (mc *MemoryCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	item, exists := mc.items[key]
	if !exists {
		// Create new item with delta value
		mc.Set(ctx, key, delta, mc.config.DefaultTTL)
		return delta, nil
	}

	// Check if expired
	if time.Now().After(item.item.ExpiresAt) {
		mc.Set(ctx, key, delta, mc.config.DefaultTTL)
		return delta, nil
	}

	// Convert value to int64
	var currentValue int64
	switch v := item.item.Value.(type) {
	case int64:
		currentValue = v
	case int:
		currentValue = int64(v)
	case float64:
		currentValue = int64(v)
	default:
		return 0, fmt.Errorf("value is not numeric")
	}

	newValue := currentValue + delta
	item.item.Value = newValue
	item.item.LastAccess = time.Now()
	mc.lruList.moveToFront(item.lruNode)

	return newValue, nil
}

// Decrement decrements a numeric value
func (mc *MemoryCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return mc.Increment(ctx, key, -delta)
}

// Touch updates the TTL of an item
func (mc *MemoryCache) Touch(ctx context.Context, key string, ttl time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	item, exists := mc.items[key]
	if !exists {
		return ErrKeyNotFound
	}

	item.item.ExpiresAt = time.Now().Add(ttl)
	item.item.TTL = ttl
	item.item.LastAccess = time.Now()
	mc.lruList.moveToFront(item.lruNode)

	return nil
}

// Clear removes all items from the cache
func (mc *MemoryCache) Clear(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.items = make(map[string]*memoryCacheItem)
	mc.lruList = newLRUList()
	mc.stats.Memory = 0
	mc.stats.Size = 0

	return nil
}

// Flush is an alias for Clear
func (mc *MemoryCache) Flush(ctx context.Context) error {
	return mc.Clear(ctx)
}

// Stats returns cache statistics
func (mc *MemoryCache) Stats(ctx context.Context) (*CacheStats, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	stats := *mc.stats // Copy stats
	stats.Uptime = time.Since(mc.startTime)

	if stats.Hits+stats.Misses > 0 {
		stats.HitRatio = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}

	return &stats, nil
}

// Type returns the cache type
func (mc *MemoryCache) Type() string {
	return "memory"
}

// Name returns the cache name
func (mc *MemoryCache) Name() string {
	return mc.name
}

// Close closes the cache and stops cleanup
func (mc *MemoryCache) Close() error {
	close(mc.stopCh)
	if mc.ticker != nil {
		mc.ticker.Stop()
	}
	return nil
}

// evictLRU evicts least recently used items
func (mc *MemoryCache) evictLRU(neededSpace int64) int {
	evicted := 0
	for {
		if mc.config.MaxSize > 0 && int64(len(mc.items)) < mc.config.MaxSize {
			if mc.config.MaxMemory == 0 || mc.stats.Memory+neededSpace <= mc.config.MaxMemory {
				break
			}
		}

		// Remove least recently used item
		if mc.lruList.tail.prev == mc.lruList.head {
			break // Empty list
		}

		lruNode := mc.lruList.tail.prev
		if item, exists := mc.items[lruNode.key]; exists {
			mc.stats.Memory -= item.size
			mc.lruList.remove(lruNode)
			delete(mc.items, lruNode.key)
			mc.stats.Evictions++
			evicted++
		}
	}

	mc.stats.Size = int64(len(mc.items))
	return evicted
}

// cleanupExpired removes expired items
func (mc *MemoryCache) cleanupExpired() {
	for {
		select {
		case <-mc.ticker.C:
			mc.cleanupExpiredItems()
		case <-mc.stopCh:
			return
		}
	}
}

// cleanupExpiredItems removes all expired items
func (mc *MemoryCache) cleanupExpiredItems() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	for key, item := range mc.items {
		if now.After(item.item.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		if item, exists := mc.items[key]; exists {
			mc.stats.Memory -= item.size
			mc.lruList.remove(item.lruNode)
			delete(mc.items, key)
			mc.stats.Evictions++
		}
	}

	mc.stats.Size = int64(len(mc.items))
}

// deleteExpired removes a specific expired item (async)
func (mc *MemoryCache) deleteExpired(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if item, exists := mc.items[key]; exists {
		if time.Now().After(item.item.ExpiresAt) {
			mc.stats.Memory -= item.size
			mc.lruList.remove(item.lruNode)
			delete(mc.items, key)
			mc.stats.Evictions++
			mc.stats.Size = int64(len(mc.items))
		}
	}
}

// calculateSize estimates the memory size of a value
func (mc *MemoryCache) calculateSize(value interface{}) int64 {
	// Simple size estimation - can be improved with reflection
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int, int32, int64, float32, float64:
		return 8
	case bool:
		return 1
	default:
		// Use reflect and unsafe for complex types
		rv := reflect.ValueOf(value)
		if rv.IsValid() {
			return int64(unsafe.Sizeof(value)) + int64(rv.Type().Size())
		}
		return int64(unsafe.Sizeof(value))
	}
}

// LRU list methods
func (l *lruList) addToFront(key string) *lruNode {
	node := &lruNode{key: key}
	node.next = l.head.next
	node.prev = l.head
	l.head.next.prev = node
	l.head.next = node
	l.size++
	return node
}

func (l *lruList) remove(node *lruNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
	l.size--
}

func (l *lruList) moveToFront(node *lruNode) {
	l.remove(node)
	newNode := l.addToFront(node.key)
	*node = *newNode // Update the node in-place
}
