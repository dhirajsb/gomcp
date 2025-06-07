package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Common errors
var (
	ErrCacheMiss    = errors.New("cache miss")
	ErrKeyNotFound  = errors.New("key not found")
	ErrSerialize    = errors.New("serialization error")
	ErrDeserialize  = errors.New("deserialization error")
	ErrTierNotFound = errors.New("cache tier not found")
	ErrCircuitOpen  = errors.New("circuit breaker open")
)

// CacheItem represents a cached item with metadata
type CacheItem struct {
	Key         string        `json:"key"`
	Value       interface{}   `json:"value"`
	ExpiresAt   time.Time     `json:"expires_at"`
	CreatedAt   time.Time     `json:"created_at"`
	AccessCount int64         `json:"access_count"`
	LastAccess  time.Time     `json:"last_access"`
	TTL         time.Duration `json:"ttl"`
	Tags        []string      `json:"tags"`
}

// Cache defines the interface for cache implementations
type Cache interface {
	// Basic operations
	Get(ctx context.Context, key string) (*CacheItem, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) bool

	// Bulk operations
	GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error)
	SetMulti(ctx context.Context, items map[string]*CacheItem) error
	DeleteMulti(ctx context.Context, keys []string) error

	// Advanced operations
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	Decrement(ctx context.Context, key string, delta int64) (int64, error)
	Touch(ctx context.Context, key string, ttl time.Duration) error

	// Maintenance
	Clear(ctx context.Context) error
	Flush(ctx context.Context) error
	Stats(ctx context.Context) (*CacheStats, error)

	// Type information
	Type() string
	Name() string
}

// CacheStats provides cache statistics
type CacheStats struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	Hits       int64         `json:"hits"`
	Misses     int64         `json:"misses"`
	Sets       int64         `json:"sets"`
	Deletes    int64         `json:"deletes"`
	Evictions  int64         `json:"evictions"`
	Size       int64         `json:"size"`
	Memory     int64         `json:"memory_bytes"`
	HitRatio   float64       `json:"hit_ratio"`
	Uptime     time.Duration `json:"uptime"`
	LastAccess time.Time     `json:"last_access"`
	ErrorCount int64         `json:"error_count"`
	LastError  string        `json:"last_error"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Name           string                 `json:"name"`
	Type           string                 `json:"type"` // "memory", "redis", "distributed"
	Enabled        bool                   `json:"enabled"`
	DefaultTTL     time.Duration          `json:"default_ttl"`
	MaxSize        int64                  `json:"max_size"`
	MaxMemory      int64                  `json:"max_memory"`
	EvictionPolicy string                 `json:"eviction_policy"` // "lru", "lfu", "fifo"
	Compression    bool                   `json:"compression"`
	Serialization  string                 `json:"serialization"` // "json", "gob", "msgpack"
	Config         map[string]interface{} `json:"config"`
}

// TierConfig defines cache tier configuration
type TierConfig struct {
	Name     string      `json:"name"`
	Level    int         `json:"level"` // 1=L1 (fastest), 2=L2, etc.
	Cache    CacheConfig `json:"cache"`
	Enabled  bool        `json:"enabled"`
	ReadOnly bool        `json:"read_only"`
	Priority int         `json:"priority"` // Higher = preferred for writes
}

// MultiTierCacheConfig defines multi-tier cache configuration
type MultiTierCacheConfig struct {
	Name           string                 `json:"name"`
	Tiers          []TierConfig           `json:"tiers"`
	WritePolicy    string                 `json:"write_policy"` // "write-through", "write-back", "write-around"
	ReadPolicy     string                 `json:"read_policy"`  // "read-through", "cache-aside"
	Promotion      bool                   `json:"promotion"`    // Promote items to higher tiers on access
	Replication    bool                   `json:"replication"`  // Replicate to multiple tiers
	Consistency    string                 `json:"consistency"`  // "eventual", "strong"
	CircuitBreaker bool                   `json:"circuit_breaker"`
	Config         map[string]interface{} `json:"config"`
}

// CacheManager manages multiple cache tiers
type CacheManager interface {
	// Cache operations
	Get(ctx context.Context, key string) (*CacheItem, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error

	// Bulk operations
	GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error)
	SetMulti(ctx context.Context, items map[string]*CacheItem) error
	DeleteMulti(ctx context.Context, keys []string) error

	// Tier management
	GetTier(name string) (Cache, error)
	AddTier(tier Cache, config TierConfig) error
	RemoveTier(name string) error
	ListTiers() []string

	// Cache management
	GetCache(name string) (Cache, error)
	RegisterCache(cache Cache) error
	UnregisterCache(name string) error

	// Maintenance
	Clear(ctx context.Context) error
	Warmup(ctx context.Context, keys []string) error
	Invalidate(ctx context.Context, pattern string) error

	// Monitoring
	Stats(ctx context.Context) (map[string]*CacheStats, error)
	Health(ctx context.Context) map[string]bool
}

// MultiTierCache implements multi-tier caching
type MultiTierCache struct {
	config         MultiTierCacheConfig
	tiers          []tierInfo
	caches         map[string]Cache
	stats          map[string]*CacheStats
	circuitBreaker map[string]*CircuitBreaker
	mu             sync.RWMutex
	startTime      time.Time
}

type tierInfo struct {
	config TierConfig
	cache  Cache
	active bool
}

// NewMultiTierCache creates a new multi-tier cache
func NewMultiTierCache(config MultiTierCacheConfig) *MultiTierCache {
	return &MultiTierCache{
		config:         config,
		tiers:          make([]tierInfo, 0),
		caches:         make(map[string]Cache),
		stats:          make(map[string]*CacheStats),
		circuitBreaker: make(map[string]*CircuitBreaker),
		startTime:      time.Now(),
	}
}

// AddTier adds a cache tier
func (mtc *MultiTierCache) AddTier(cache Cache, config TierConfig) error {
	mtc.mu.Lock()
	defer mtc.mu.Unlock()

	// Check if tier already exists
	for _, tier := range mtc.tiers {
		if tier.config.Name == config.Name {
			return fmt.Errorf("tier %s already exists", config.Name)
		}
	}

	tier := tierInfo{
		config: config,
		cache:  cache,
		active: config.Enabled,
	}

	// Insert tier in correct position based on level
	inserted := false
	for i, existing := range mtc.tiers {
		if config.Level < existing.config.Level {
			mtc.tiers = append(mtc.tiers[:i], append([]tierInfo{tier}, mtc.tiers[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		mtc.tiers = append(mtc.tiers, tier)
	}

	// Register cache
	mtc.caches[cache.Name()] = cache

	// Initialize circuit breaker if enabled
	if mtc.config.CircuitBreaker {
		mtc.circuitBreaker[config.Name] = NewCircuitBreaker(CircuitBreakerConfig{
			MaxFailures: 5,
			Timeout:     30 * time.Second,
		})
	}

	return nil
}

// RemoveTier removes a cache tier
func (mtc *MultiTierCache) RemoveTier(name string) error {
	mtc.mu.Lock()
	defer mtc.mu.Unlock()

	for i, tier := range mtc.tiers {
		if tier.config.Name == name {
			mtc.tiers = append(mtc.tiers[:i], mtc.tiers[i+1:]...)
			delete(mtc.caches, tier.cache.Name())
			delete(mtc.circuitBreaker, name)
			return nil
		}
	}

	return ErrTierNotFound
}

// Get retrieves an item from cache tiers
func (mtc *MultiTierCache) Get(ctx context.Context, key string) (*CacheItem, error) {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	var foundItem *CacheItem
	var foundTier int = -1

	// Search through tiers in order (L1 first)
	for i, tier := range mtc.tiers {
		if !tier.active {
			continue
		}

		// Check circuit breaker
		if cb, exists := mtc.circuitBreaker[tier.config.Name]; exists {
			if !cb.CanExecute() {
				continue
			}
		}

		item, err := tier.cache.Get(ctx, key)
		if err == nil && item != nil {
			foundItem = item
			foundTier = i
			break
		}

		// Record circuit breaker failure
		if cb, exists := mtc.circuitBreaker[tier.config.Name]; exists && err != ErrCacheMiss {
			cb.RecordFailure()
		}
	}

	if foundItem == nil {
		return nil, ErrCacheMiss
	}

	// Promote item to higher tiers if enabled
	if mtc.config.Promotion && foundTier > 0 {
		go mtc.promoteItem(context.Background(), key, foundItem, foundTier)
	}

	// Record circuit breaker success
	if foundTier >= 0 {
		if cb, exists := mtc.circuitBreaker[mtc.tiers[foundTier].config.Name]; exists {
			cb.RecordSuccess()
		}
	}

	return foundItem, nil
}

// Set stores an item in cache tiers
func (mtc *MultiTierCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	item := &CacheItem{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
		TTL:       ttl,
	}

	switch mtc.config.WritePolicy {
	case "write-through":
		return mtc.writeThrough(ctx, key, item)
	case "write-back":
		return mtc.writeBack(ctx, key, item)
	case "write-around":
		return mtc.writeAround(ctx, key, item)
	default:
		return mtc.writeThrough(ctx, key, item)
	}
}

// writeThrough writes to all available tiers
func (mtc *MultiTierCache) writeThrough(ctx context.Context, key string, item *CacheItem) error {
	var lastErr error

	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		// Check circuit breaker
		if cb, exists := mtc.circuitBreaker[tier.config.Name]; exists {
			if !cb.CanExecute() {
				continue
			}
		}

		err := tier.cache.Set(ctx, key, item.Value, item.TTL)
		if err != nil {
			lastErr = err
			// Record circuit breaker failure
			if cb, exists := mtc.circuitBreaker[tier.config.Name]; exists {
				cb.RecordFailure()
			}
		} else {
			// Record circuit breaker success
			if cb, exists := mtc.circuitBreaker[tier.config.Name]; exists {
				cb.RecordSuccess()
			}
		}
	}

	return lastErr
}

// writeBack writes to fastest tier, syncs later
func (mtc *MultiTierCache) writeBack(ctx context.Context, key string, item *CacheItem) error {
	// Write to first available tier
	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		err := tier.cache.Set(ctx, key, item.Value, item.TTL)
		if err == nil {
			// Schedule background sync to other tiers
			go mtc.syncToOtherTiers(context.Background(), key, item, tier.config.Name)
			return nil
		}
	}

	return fmt.Errorf("no available cache tiers")
}

// writeAround bypasses cache and writes to storage
func (mtc *MultiTierCache) writeAround(ctx context.Context, key string, item *CacheItem) error {
	// Write to highest level tier only (usually persistent storage)
	if len(mtc.tiers) == 0 {
		return fmt.Errorf("no cache tiers available")
	}

	lastTier := mtc.tiers[len(mtc.tiers)-1]
	if !lastTier.active || lastTier.config.ReadOnly {
		return fmt.Errorf("last tier not available for writes")
	}

	return lastTier.cache.Set(ctx, key, item.Value, item.TTL)
}

// promoteItem promotes an item to higher cache tiers
func (mtc *MultiTierCache) promoteItem(ctx context.Context, key string, item *CacheItem, foundTier int) {
	for i := 0; i < foundTier; i++ {
		tier := mtc.tiers[i]
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		tier.cache.Set(ctx, key, item.Value, item.TTL)
	}
}

// syncToOtherTiers syncs an item to other cache tiers
func (mtc *MultiTierCache) syncToOtherTiers(ctx context.Context, key string, item *CacheItem, excludeTier string) {
	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly || tier.config.Name == excludeTier {
			continue
		}

		tier.cache.Set(ctx, key, item.Value, item.TTL)
	}
}

// Delete removes an item from all cache tiers
func (mtc *MultiTierCache) Delete(ctx context.Context, key string) error {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	var lastErr error

	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		err := tier.cache.Delete(ctx, key)
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// GetMulti retrieves multiple items
func (mtc *MultiTierCache) GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error) {
	result := make(map[string]*CacheItem)
	remaining := make([]string, len(keys))
	copy(remaining, keys)

	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	// Search through tiers
	for tierIndex, tier := range mtc.tiers {
		if !tier.active || len(remaining) == 0 {
			continue
		}

		items, err := tier.cache.GetMulti(ctx, remaining)
		if err != nil {
			continue
		}

		// Collect found items
		var stillRemaining []string
		for _, key := range remaining {
			if item, found := items[key]; found {
				result[key] = item

				// Promote to higher tiers if enabled
				if mtc.config.Promotion && tierIndex > 0 {
					go mtc.promoteItem(context.Background(), key, item, tierIndex)
				}
			} else {
				stillRemaining = append(stillRemaining, key)
			}
		}

		remaining = stillRemaining
	}

	return result, nil
}

// SetMulti stores multiple items
func (mtc *MultiTierCache) SetMulti(ctx context.Context, items map[string]*CacheItem) error {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	var lastErr error

	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		err := tier.cache.SetMulti(ctx, items)
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// DeleteMulti removes multiple items
func (mtc *MultiTierCache) DeleteMulti(ctx context.Context, keys []string) error {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	var lastErr error

	for _, tier := range mtc.tiers {
		if !tier.active || tier.config.ReadOnly {
			continue
		}

		err := tier.cache.DeleteMulti(ctx, keys)
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// GetTier returns a specific cache tier
func (mtc *MultiTierCache) GetTier(name string) (Cache, error) {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	for _, tier := range mtc.tiers {
		if tier.config.Name == name {
			return tier.cache, nil
		}
	}

	return nil, ErrTierNotFound
}

// GetCache returns a cache by name
func (mtc *MultiTierCache) GetCache(name string) (Cache, error) {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	if cache, exists := mtc.caches[name]; exists {
		return cache, nil
	}

	return nil, fmt.Errorf("cache %s not found", name)
}

// RegisterCache registers a cache
func (mtc *MultiTierCache) RegisterCache(cache Cache) error {
	mtc.mu.Lock()
	defer mtc.mu.Unlock()

	mtc.caches[cache.Name()] = cache
	return nil
}

// UnregisterCache unregisters a cache
func (mtc *MultiTierCache) UnregisterCache(name string) error {
	mtc.mu.Lock()
	defer mtc.mu.Unlock()

	delete(mtc.caches, name)
	return nil
}

// ListTiers returns names of all cache tiers
func (mtc *MultiTierCache) ListTiers() []string {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	names := make([]string, len(mtc.tiers))
	for i, tier := range mtc.tiers {
		names[i] = tier.config.Name
	}

	return names
}

// Clear clears all cache tiers
func (mtc *MultiTierCache) Clear(ctx context.Context) error {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	var lastErr error

	for _, tier := range mtc.tiers {
		if !tier.active {
			continue
		}

		err := tier.cache.Clear(ctx)
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Warmup preloads cache with specified keys
func (mtc *MultiTierCache) Warmup(ctx context.Context, keys []string) error {
	// Implementation would depend on data source
	return fmt.Errorf("warmup not implemented")
}

// Invalidate removes items matching pattern
func (mtc *MultiTierCache) Invalidate(ctx context.Context, pattern string) error {
	// Implementation would depend on cache capabilities
	return fmt.Errorf("invalidate not implemented")
}

// Stats returns statistics for all cache tiers
func (mtc *MultiTierCache) Stats(ctx context.Context) (map[string]*CacheStats, error) {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	stats := make(map[string]*CacheStats)

	for _, tier := range mtc.tiers {
		if tierStats, err := tier.cache.Stats(ctx); err == nil {
			stats[tier.config.Name] = tierStats
		}
	}

	return stats, nil
}

// Health returns health status of all cache tiers
func (mtc *MultiTierCache) Health(ctx context.Context) map[string]bool {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	health := make(map[string]bool)

	for _, tier := range mtc.tiers {
		// Simple health check - try to get stats
		_, err := tier.cache.Stats(ctx)
		health[tier.config.Name] = err == nil
	}

	return health
}
