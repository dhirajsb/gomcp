package metrics

import (
	"log"
)

// SimpleProvider implements a simple metrics provider that logs to console
type SimpleProvider struct {
	name string
}

// NewSimple creates a new simple metrics provider
func NewSimple(name string) *SimpleProvider {
	return &SimpleProvider{name: name}
}

func (smp *SimpleProvider) Name() string {
	return smp.name
}

func (smp *SimpleProvider) RecordCounter(name string, value int64, labels map[string]string) {
	log.Printf("[METRICS] Counter %s: %d %v", name, value, labels)
}

func (smp *SimpleProvider) RecordGauge(name string, value float64, labels map[string]string) {
	log.Printf("[METRICS] Gauge %s: %f %v", name, value, labels)
}

func (smp *SimpleProvider) RecordHistogram(name string, value float64, labels map[string]string) {
	log.Printf("[METRICS] Histogram %s: %f %v", name, value, labels)
}

func (smp *SimpleProvider) Close() error {
	return nil
}
