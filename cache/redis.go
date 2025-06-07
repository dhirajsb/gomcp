package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements cache using Redis
type RedisCache struct {
	name      string
	config    CacheConfig
	client    redis.UniversalClient
	stats     *CacheStats
	startTime time.Time
}

// RedisConfig holds Redis-specific configuration
type RedisConfig struct {
	Addrs        []string `json:"addrs"`         // Redis addresses
	Username     string   `json:"username"`      // Redis username
	Password     string   `json:"password"`      // Redis password
	DB           int      `json:"db"`            // Database number
	PoolSize     int      `json:"pool_size"`     // Connection pool size
	MinIdleConns int      `json:"min_idle_conns"` // Minimum idle connections
	MaxRetries   int      `json:"max_retries"`   // Maximum retries
	DialTimeout  string   `json:"dial_timeout"`  // Connection timeout
	ReadTimeout  string   `json:"read_timeout"`  // Read timeout
	WriteTimeout string   `json:"write_timeout"` // Write timeout
	Cluster      bool     `json:"cluster"`       // Enable cluster mode
	Sentinel     bool     `json:"sentinel"`      // Enable sentinel mode
	MasterName   string   `json:"master_name"`   // Sentinel master name
	KeyPrefix    string   `json:"key_prefix"`    // Key prefix for namespacing
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(name string, config CacheConfig) (*RedisCache, error) {
	// Parse Redis configuration
	redisConfig := parseRedisConfig(config.Config)
	
	// Create Redis client
	var client redis.UniversalClient
	
	if redisConfig.Cluster {
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        redisConfig.Addrs,
			Username:     redisConfig.Username,
			Password:     redisConfig.Password,
			PoolSize:     redisConfig.PoolSize,
			MinIdleConns: redisConfig.MinIdleConns,
			MaxRetries:   redisConfig.MaxRetries,
			DialTimeout:  parseDuration(redisConfig.DialTimeout, 5*time.Second),
			ReadTimeout:  parseDuration(redisConfig.ReadTimeout, 3*time.Second),
			WriteTimeout: parseDuration(redisConfig.WriteTimeout, 3*time.Second),
		})
	} else if redisConfig.Sentinel {
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    redisConfig.MasterName,
			SentinelAddrs: redisConfig.Addrs,
			Username:      redisConfig.Username,
			Password:      redisConfig.Password,
			DB:            redisConfig.DB,
			PoolSize:      redisConfig.PoolSize,
			MinIdleConns:  redisConfig.MinIdleConns,
			MaxRetries:    redisConfig.MaxRetries,
			DialTimeout:   parseDuration(redisConfig.DialTimeout, 5*time.Second),
			ReadTimeout:   parseDuration(redisConfig.ReadTimeout, 3*time.Second),
			WriteTimeout:  parseDuration(redisConfig.WriteTimeout, 3*time.Second),
		})
	} else {
		addr := "localhost:6379"
		if len(redisConfig.Addrs) > 0 {
			addr = redisConfig.Addrs[0]
		}
		
		client = redis.NewClient(&redis.Options{
			Addr:         addr,
			Username:     redisConfig.Username,
			Password:     redisConfig.Password,
			DB:           redisConfig.DB,
			PoolSize:     redisConfig.PoolSize,
			MinIdleConns: redisConfig.MinIdleConns,
			MaxRetries:   redisConfig.MaxRetries,
			DialTimeout:  parseDuration(redisConfig.DialTimeout, 5*time.Second),
			ReadTimeout:  parseDuration(redisConfig.ReadTimeout, 3*time.Second),
			WriteTimeout: parseDuration(redisConfig.WriteTimeout, 3*time.Second),
		})
	}
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	
	return &RedisCache{
		name:   name,
		config: config,
		client: client,
		stats: &CacheStats{
			Name: name,
			Type: "redis",
		},
		startTime: time.Now(),
	}, nil
}

// parseRedisConfig parses Redis configuration from generic config map
func parseRedisConfig(config map[string]interface{}) RedisConfig {
	redisConfig := RedisConfig{
		Addrs:        []string{"localhost:6379"},
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 5,
		MaxRetries:   3,
		DialTimeout:  "5s",
		ReadTimeout:  "3s",
		WriteTimeout: "3s",
	}
	
	if addrs, ok := config["addrs"].([]interface{}); ok {
		redisConfig.Addrs = make([]string, len(addrs))
		for i, addr := range addrs {
			redisConfig.Addrs[i] = fmt.Sprintf("%v", addr)
		}
	} else if addr, ok := config["addr"].(string); ok {
		redisConfig.Addrs = []string{addr}
	}
	
	if username, ok := config["username"].(string); ok {
		redisConfig.Username = username
	}
	if password, ok := config["password"].(string); ok {
		redisConfig.Password = password
	}
	if db, ok := config["db"].(float64); ok {
		redisConfig.DB = int(db)
	}
	if poolSize, ok := config["pool_size"].(float64); ok {
		redisConfig.PoolSize = int(poolSize)
	}
	if minIdleConns, ok := config["min_idle_conns"].(float64); ok {
		redisConfig.MinIdleConns = int(minIdleConns)
	}
	if maxRetries, ok := config["max_retries"].(float64); ok {
		redisConfig.MaxRetries = int(maxRetries)
	}
	if dialTimeout, ok := config["dial_timeout"].(string); ok {
		redisConfig.DialTimeout = dialTimeout
	}
	if readTimeout, ok := config["read_timeout"].(string); ok {
		redisConfig.ReadTimeout = readTimeout
	}
	if writeTimeout, ok := config["write_timeout"].(string); ok {
		redisConfig.WriteTimeout = writeTimeout
	}
	if cluster, ok := config["cluster"].(bool); ok {
		redisConfig.Cluster = cluster
	}
	if sentinel, ok := config["sentinel"].(bool); ok {
		redisConfig.Sentinel = sentinel
	}
	if masterName, ok := config["master_name"].(string); ok {
		redisConfig.MasterName = masterName
	}
	if keyPrefix, ok := config["key_prefix"].(string); ok {
		redisConfig.KeyPrefix = keyPrefix
	}
	
	return redisConfig
}

// parseDuration parses a duration string with fallback
func parseDuration(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

// makeKey creates a Redis key with optional prefix
func (rc *RedisCache) makeKey(key string) string {
	if redisConfig := parseRedisConfig(rc.config.Config); redisConfig.KeyPrefix != "" {
		return redisConfig.KeyPrefix + ":" + key
	}
	return key
}

// Get retrieves an item from Redis
func (rc *RedisCache) Get(ctx context.Context, key string) (*CacheItem, error) {
	redisKey := rc.makeKey(key)
	
	// Get JSON data from Redis
	data, err := rc.client.Get(ctx, redisKey).Result()
	if err != nil {
		if err == redis.Nil {
			rc.stats.Misses++
			return nil, ErrCacheMiss
		}
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return nil, err
	}
	
	// Deserialize cache item
	var item CacheItem
	if err := json.Unmarshal([]byte(data), &item); err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return nil, ErrDeserialize
	}
	
	// Check if expired (Redis should handle this, but double-check)
	if time.Now().After(item.ExpiresAt) {
		rc.stats.Misses++
		go rc.client.Del(context.Background(), redisKey) // Clean up asynchronously
		return nil, ErrCacheMiss
	}
	
	// Update access info
	item.AccessCount++
	item.LastAccess = time.Now()
	
	// Update item in Redis (fire and forget)
	go func() {
		if itemData, err := json.Marshal(item); err == nil {
			rc.client.Set(context.Background(), redisKey, itemData, time.Until(item.ExpiresAt))
		}
	}()
	
	rc.stats.Hits++
	rc.stats.LastAccess = time.Now()
	return &item, nil
}

// Set stores an item in Redis
func (rc *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = rc.config.DefaultTTL
	}
	
	redisKey := rc.makeKey(key)
	now := time.Now()
	
	item := CacheItem{
		Key:         key,
		Value:       value,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
		AccessCount: 0,
		LastAccess:  now,
		TTL:         ttl,
	}
	
	// Serialize cache item
	data, err := json.Marshal(item)
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return ErrSerialize
	}
	
	// Store in Redis with TTL
	err = rc.client.Set(ctx, redisKey, data, ttl).Err()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	rc.stats.Sets++
	return nil
}

// Delete removes an item from Redis
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	redisKey := rc.makeKey(key)
	
	err := rc.client.Del(ctx, redisKey).Err()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	rc.stats.Deletes++
	return nil
}

// Exists checks if a key exists in Redis
func (rc *RedisCache) Exists(ctx context.Context, key string) bool {
	redisKey := rc.makeKey(key)
	
	count, err := rc.client.Exists(ctx, redisKey).Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return false
	}
	
	return count > 0
}

// GetMulti retrieves multiple items from Redis
func (rc *RedisCache) GetMulti(ctx context.Context, keys []string) (map[string]*CacheItem, error) {
	if len(keys) == 0 {
		return make(map[string]*CacheItem), nil
	}
	
	// Convert keys to Redis keys
	redisKeys := make([]string, len(keys))
	keyMap := make(map[string]string) // redisKey -> originalKey
	for i, key := range keys {
		redisKey := rc.makeKey(key)
		redisKeys[i] = redisKey
		keyMap[redisKey] = key
	}
	
	// Get all values
	values, err := rc.client.MGet(ctx, redisKeys...).Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return nil, err
	}
	
	result := make(map[string]*CacheItem)
	
	for i, value := range values {
		if value == nil {
			rc.stats.Misses++
			continue
		}
		
		// Deserialize cache item
		var item CacheItem
		if err := json.Unmarshal([]byte(value.(string)), &item); err != nil {
			rc.stats.Misses++
			continue
		}
		
		// Check if expired
		if time.Now().After(item.ExpiresAt) {
			rc.stats.Misses++
			go rc.client.Del(context.Background(), redisKeys[i])
			continue
		}
		
		originalKey := keyMap[redisKeys[i]]
		result[originalKey] = &item
		rc.stats.Hits++
	}
	
	rc.stats.LastAccess = time.Now()
	return result, nil
}

// SetMulti stores multiple items in Redis
func (rc *RedisCache) SetMulti(ctx context.Context, items map[string]*CacheItem) error {
	if len(items) == 0 {
		return nil
	}
	
	pipe := rc.client.Pipeline()
	
	for key, item := range items {
		redisKey := rc.makeKey(key)
		
		// Serialize cache item
		data, err := json.Marshal(item)
		if err != nil {
			rc.stats.ErrorCount++
			rc.stats.LastError = err.Error()
			continue
		}
		
		ttl := time.Until(item.ExpiresAt)
		if ttl <= 0 {
			ttl = rc.config.DefaultTTL
		}
		
		pipe.Set(ctx, redisKey, data, ttl)
	}
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	rc.stats.Sets += int64(len(items))
	return nil
}

// DeleteMulti removes multiple items from Redis
func (rc *RedisCache) DeleteMulti(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	
	redisKeys := make([]string, len(keys))
	for i, key := range keys {
		redisKeys[i] = rc.makeKey(key)
	}
	
	deleted, err := rc.client.Del(ctx, redisKeys...).Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	rc.stats.Deletes += deleted
	return nil
}

// Increment increments a numeric value in Redis
func (rc *RedisCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	redisKey := rc.makeKey(key)
	
	result, err := rc.client.IncrBy(ctx, redisKey, delta).Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return 0, err
	}
	
	// Set TTL if key is new
	if result == delta {
		rc.client.Expire(ctx, redisKey, rc.config.DefaultTTL)
	}
	
	return result, nil
}

// Decrement decrements a numeric value in Redis
func (rc *RedisCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return rc.Increment(ctx, key, -delta)
}

// Touch updates the TTL of an item in Redis
func (rc *RedisCache) Touch(ctx context.Context, key string, ttl time.Duration) error {
	redisKey := rc.makeKey(key)
	
	success, err := rc.client.Expire(ctx, redisKey, ttl).Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	if !success {
		return ErrKeyNotFound
	}
	
	return nil
}

// Clear removes all items from Redis (flushes the database)
func (rc *RedisCache) Clear(ctx context.Context) error {
	// This is dangerous - it clears the entire database
	// In production, you might want to use a pattern-based delete
	err := rc.client.FlushDB(ctx).Err()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return err
	}
	
	return nil
}

// Flush is an alias for Clear
func (rc *RedisCache) Flush(ctx context.Context) error {
	return rc.Clear(ctx)
}

// Stats returns cache statistics
func (rc *RedisCache) Stats(ctx context.Context) (*CacheStats, error) {
	// Get Redis INFO stats
	info, err := rc.client.Info(ctx, "stats", "memory").Result()
	if err != nil {
		rc.stats.ErrorCount++
		rc.stats.LastError = err.Error()
		return rc.stats, err
	}
	
	// Parse INFO output
	lines := strings.Split(info, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key, value := parts[0], parts[1]
				switch key {
				case "keyspace_hits":
					if hits, err := strconv.ParseInt(value, 10, 64); err == nil {
						rc.stats.Hits = hits
					}
				case "keyspace_misses":
					if misses, err := strconv.ParseInt(value, 10, 64); err == nil {
						rc.stats.Misses = misses
					}
				case "used_memory":
					if memory, err := strconv.ParseInt(value, 10, 64); err == nil {
						rc.stats.Memory = memory
					}
				}
			}
		}
	}
	
	// Calculate derived stats
	stats := *rc.stats // Copy stats
	stats.Uptime = time.Since(rc.startTime)
	
	if stats.Hits+stats.Misses > 0 {
		stats.HitRatio = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}
	
	return &stats, nil
}

// Type returns the cache type
func (rc *RedisCache) Type() string {
	return "redis"
}

// Name returns the cache name
func (rc *RedisCache) Name() string {
	return rc.name
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}