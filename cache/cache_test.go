package cache

import (
	"context"
	"testing"
	"time"
)

func TestNewMultiTierCache(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:           "test-cache",
		WritePolicy:    "write-through",
		ReadPolicy:     "read-through",
		Promotion:      true,
		Replication:    false,
		Consistency:    "eventual",
		CircuitBreaker: true,
	}

	cache := NewMultiTierCache(config)
	if cache == nil {
		t.Fatal("Expected cache to be created")
	}

	if cache.config.Name != "test-cache" {
		t.Errorf("Expected cache name test-cache, got %s", cache.config.Name)
	}

	if len(cache.tiers) != 0 {
		t.Errorf("Expected 0 tiers initially, got %d", len(cache.tiers))
	}
}

func TestMultiTierCache_AddTier(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Create mock cache
	mockCache := NewMockCache("L1", "memory")
	tierConfig := TierConfig{
		Name:     "L1",
		Level:    1,
		Enabled:  true,
		ReadOnly: false,
		Priority: 100,
	}

	err := cache.AddTier(mockCache, tierConfig)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(cache.tiers) != 1 {
		t.Errorf("Expected 1 tier, got %d", len(cache.tiers))
	}

	// Try to add duplicate tier
	err = cache.AddTier(mockCache, tierConfig)
	if err == nil {
		t.Error("Expected error when adding duplicate tier")
	}
}

func TestMultiTierCache_SetGet(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:        "test-cache",
		WritePolicy: "write-through",
	}
	cache := NewMultiTierCache(config)

	// Add L1 cache
	l1Cache := NewMockCache("L1", "memory")
	l1Config := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(l1Cache, l1Config)

	// Add L2 cache
	l2Cache := NewMockCache("L2", "redis")
	l2Config := TierConfig{Name: "L2", Level: 2, Enabled: true}
	cache.AddTier(l2Cache, l2Config)

	ctx := context.Background()

	// Set a value
	err := cache.Set(ctx, "test-key", "test-value", time.Hour)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify both caches have the value (write-through)
	if !l1Cache.HasKey("test-key") {
		t.Error("Expected L1 cache to have the key")
	}
	if !l2Cache.HasKey("test-key") {
		t.Error("Expected L2 cache to have the key")
	}

	// Get the value
	item, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if item.Value != "test-value" {
		t.Errorf("Expected test-value, got %v", item.Value)
	}
}

func TestMultiTierCache_GetPromotion(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:      "test-cache",
		Promotion: true,
	}
	cache := NewMultiTierCache(config)

	// Add L1 cache
	l1Cache := NewMockCache("L1", "memory")
	l1Config := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(l1Cache, l1Config)

	// Add L2 cache
	l2Cache := NewMockCache("L2", "redis")
	l2Config := TierConfig{Name: "L2", Level: 2, Enabled: true}
	cache.AddTier(l2Cache, l2Config)

	ctx := context.Background()

	// Set value only in L2
	item := &CacheItem{
		Key:       "test-key",
		Value:     "test-value",
		ExpiresAt: time.Now().Add(time.Hour),
		TTL:       time.Hour,
	}
	l2Cache.SetItem("test-key", item)

	// Get the value - should come from L2 and be promoted to L1
	retrieved, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if retrieved.Value != "test-value" {
		t.Errorf("Expected test-value, got %v", retrieved.Value)
	}

	// Give time for promotion to complete
	time.Sleep(100 * time.Millisecond)

	// L1 should now have the key (promoted)
	if !l1Cache.HasKey("test-key") {
		t.Error("Expected L1 cache to have promoted key")
	}
}

func TestMultiTierCache_Delete(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Add caches
	l1Cache := NewMockCache("L1", "memory")
	l1Config := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(l1Cache, l1Config)

	l2Cache := NewMockCache("L2", "redis")
	l2Config := TierConfig{Name: "L2", Level: 2, Enabled: true}
	cache.AddTier(l2Cache, l2Config)

	ctx := context.Background()

	// Set value in both caches
	cache.Set(ctx, "test-key", "test-value", time.Hour)

	// Delete the value
	err := cache.Delete(ctx, "test-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify both caches don't have the value
	if l1Cache.HasKey("test-key") {
		t.Error("Expected L1 cache to not have the key")
	}
	if l2Cache.HasKey("test-key") {
		t.Error("Expected L2 cache to not have the key")
	}
}

func TestMultiTierCache_GetMulti(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Add cache
	mockCache := NewMockCache("L1", "memory")
	tierConfig := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(mockCache, tierConfig)

	ctx := context.Background()

	// Set multiple values
	keys := []string{"key1", "key2", "key3"}
	for i, key := range keys {
		cache.Set(ctx, key, i, time.Hour)
	}

	// Get multiple values
	results, err := cache.GetMulti(ctx, keys)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	for i, key := range keys {
		if results[key].Value != i {
			t.Errorf("Expected value %d for key %s, got %v", i, key, results[key].Value)
		}
	}
}

func TestMultiTierCache_RemoveTier(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Add tier
	mockCache := NewMockCache("L1", "memory")
	tierConfig := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(mockCache, tierConfig)

	// Remove tier
	err := cache.RemoveTier("L1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(cache.tiers) != 0 {
		t.Errorf("Expected 0 tiers after removal, got %d", len(cache.tiers))
	}

	// Try to remove non-existent tier
	err = cache.RemoveTier("nonexistent")
	if err != ErrTierNotFound {
		t.Errorf("Expected ErrTierNotFound, got %v", err)
	}
}

func TestMultiTierCache_WriteBack(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:        "test-cache",
		WritePolicy: "write-back",
	}
	cache := NewMultiTierCache(config)

	// Add L1 cache
	l1Cache := NewMockCache("L1", "memory")
	l1Config := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(l1Cache, l1Config)

	// Add L2 cache
	l2Cache := NewMockCache("L2", "redis")
	l2Config := TierConfig{Name: "L2", Level: 2, Enabled: true}
	cache.AddTier(l2Cache, l2Config)

	ctx := context.Background()

	// Set a value (write-back should write to L1 first)
	err := cache.Set(ctx, "test-key", "test-value", time.Hour)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// L1 should have the value immediately
	if !l1Cache.HasKey("test-key") {
		t.Error("Expected L1 cache to have the key")
	}

	// Give time for background sync
	time.Sleep(100 * time.Millisecond)

	// L2 should eventually have the value
	if !l2Cache.HasKey("test-key") {
		t.Error("Expected L2 cache to have the key after sync")
	}
}

func TestMultiTierCache_WriteAround(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:        "test-cache",
		WritePolicy: "write-around",
	}
	cache := NewMultiTierCache(config)

	// Add L1 cache
	l1Cache := NewMockCache("L1", "memory")
	l1Config := TierConfig{Name: "L1", Level: 1, Enabled: true}
	cache.AddTier(l1Cache, l1Config)

	// Add L2 cache (last tier)
	l2Cache := NewMockCache("L2", "redis")
	l2Config := TierConfig{Name: "L2", Level: 2, Enabled: true}
	cache.AddTier(l2Cache, l2Config)

	ctx := context.Background()

	// Set a value (write-around should write to last tier only)
	err := cache.Set(ctx, "test-key", "test-value", time.Hour)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// L1 should NOT have the value
	if l1Cache.HasKey("test-key") {
		t.Error("Expected L1 cache to NOT have the key with write-around")
	}

	// L2 should have the value
	if !l2Cache.HasKey("test-key") {
		t.Error("Expected L2 cache to have the key with write-around")
	}
}

func TestMultiTierCache_Health(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Add healthy cache
	healthyCache := NewMockCache("healthy", "memory")
	healthyConfig := TierConfig{Name: "healthy", Level: 1, Enabled: true}
	cache.AddTier(healthyCache, healthyConfig)

	// Add unhealthy cache
	unhealthyCache := NewMockCache("unhealthy", "redis")
	unhealthyCache.SetError(true) // Make it return errors
	unhealthyConfig := TierConfig{Name: "unhealthy", Level: 2, Enabled: true}
	cache.AddTier(unhealthyCache, unhealthyConfig)

	ctx := context.Background()
	health := cache.Health(ctx)

	if len(health) != 2 {
		t.Errorf("Expected health for 2 tiers, got %d", len(health))
	}

	if !health["healthy"] {
		t.Error("Expected healthy cache to be healthy")
	}

	if health["unhealthy"] {
		t.Error("Expected unhealthy cache to be unhealthy")
	}
}

func TestMultiTierCache_Stats(t *testing.T) {
	config := MultiTierCacheConfig{Name: "test-cache"}
	cache := NewMultiTierCache(config)

	// Add cache
	mockCache := NewMockCache("test", "memory")
	tierConfig := TierConfig{Name: "test", Level: 1, Enabled: true}
	cache.AddTier(mockCache, tierConfig)

	ctx := context.Background()
	stats, err := cache.Stats(ctx)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(stats) != 1 {
		t.Errorf("Expected stats for 1 tier, got %d", len(stats))
	}

	if stats["test"] == nil {
		t.Error("Expected stats for test tier")
	}
}

func TestCacheItem(t *testing.T) {
	now := time.Now()
	item := &CacheItem{
		Key:         "test-key",
		Value:       "test-value",
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
		AccessCount: 5,
		LastAccess:  now,
		TTL:         time.Hour,
		Tags:        []string{"tag1", "tag2"},
	}

	if item.Key != "test-key" {
		t.Errorf("Expected key test-key, got %s", item.Key)
	}

	if item.Value != "test-value" {
		t.Errorf("Expected value test-value, got %v", item.Value)
	}

	if item.AccessCount != 5 {
		t.Errorf("Expected access count 5, got %d", item.AccessCount)
	}

	if len(item.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(item.Tags))
	}
}

func TestCacheStats(t *testing.T) {
	stats := &CacheStats{
		Name:       "test-cache",
		Type:       "memory",
		Hits:       100,
		Misses:     10,
		Sets:       50,
		Deletes:    5,
		Evictions:  2,
		Size:       1000,
		Memory:     1024 * 1024,
		HitRatio:   0.91,
		Uptime:     time.Hour,
		LastAccess: time.Now(),
		ErrorCount: 1,
		LastError:  "test error",
	}

	if stats.Name != "test-cache" {
		t.Errorf("Expected name test-cache, got %s", stats.Name)
	}

	if stats.HitRatio != 0.91 {
		t.Errorf("Expected hit ratio 0.91, got %f", stats.HitRatio)
	}

	if stats.ErrorCount != 1 {
		t.Errorf("Expected error count 1, got %d", stats.ErrorCount)
	}
}

func TestTierConfig(t *testing.T) {
	config := TierConfig{
		Name:     "L1",
		Level:    1,
		Enabled:  true,
		ReadOnly: false,
		Priority: 100,
		Cache: CacheConfig{
			Name:       "memory-cache",
			Type:       "memory",
			Enabled:    true,
			DefaultTTL: time.Hour,
			MaxSize:    1000,
		},
	}

	if config.Name != "L1" {
		t.Errorf("Expected name L1, got %s", config.Name)
	}

	if config.Level != 1 {
		t.Errorf("Expected level 1, got %d", config.Level)
	}

	if config.Cache.Type != "memory" {
		t.Errorf("Expected cache type memory, got %s", config.Cache.Type)
	}
}

func TestMultiTierCacheConfig(t *testing.T) {
	config := MultiTierCacheConfig{
		Name:           "enterprise-cache",
		WritePolicy:    "write-through",
		ReadPolicy:     "read-through",
		Promotion:      true,
		Replication:    false,
		Consistency:    "eventual",
		CircuitBreaker: true,
		Tiers: []TierConfig{
			{Name: "L1", Level: 1},
			{Name: "L2", Level: 2},
		},
	}

	if config.Name != "enterprise-cache" {
		t.Errorf("Expected name enterprise-cache, got %s", config.Name)
	}

	if len(config.Tiers) != 2 {
		t.Errorf("Expected 2 tiers, got %d", len(config.Tiers))
	}

	if !config.Promotion {
		t.Error("Expected promotion to be enabled")
	}

	if config.Replication {
		t.Error("Expected replication to be disabled")
	}
}
