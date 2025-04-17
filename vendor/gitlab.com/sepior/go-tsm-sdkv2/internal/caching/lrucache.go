package caching

import (
	"sync"
)

type lruCache struct {
	mu   sync.Mutex
	gs   *lru
	size int
}

func NewLRUCache(size int) *lruCache {
	return &lruCache{
		gs:   newLRU(size),
		size: size,
	}
}

func (c *lruCache) GetOrSet(key interface{}, data interface{}, f func(key interface{}, data interface{}) (interface{}, error)) (interface{}, error) {
	if c == nil || c.size == 0 {
		return f(key, data)
	}

	c.mu.Lock()
	if v, ok := c.gs.Get(key); ok {
		return c.retrieve(v)
	}
	return c.store(key, data, f)
}

func (c *lruCache) store(key interface{}, data interface{}, f func(key interface{}, data interface{}) (interface{}, error)) (interface{}, error) {
	e := &entry{ready: make(chan struct{})}
	c.gs.Set(key, e)
	c.mu.Unlock()
	e.result.value, e.result.err = f(key, data)
	close(e.ready)
	return e.result.value, e.result.err
}

func (c *lruCache) retrieve(v interface{}) (interface{}, error) {
	e := v.(*entry)
	c.mu.Unlock()
	<-e.ready
	return e.result.value, e.result.err
}

func (c *lruCache) Capacity() int {
	if c == nil {
		return 0
	}
	return c.size
}

type entry struct {
	result result
	ready  chan struct{}
}

type result struct {
	value interface{}
	err   error
}
