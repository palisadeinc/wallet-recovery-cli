package caching

type Cache interface {
	GetOrSet(key interface{}, data interface{}, f func(key interface{}, data interface{}) (interface{}, error)) (interface{}, error)
	Capacity() int
}

type noCache struct{}

func NoCache() *noCache {
	return &noCache{}
}

func (c *noCache) GetOrSet(key interface{}, data interface{}, f func(key interface{}, data interface{}) (interface{}, error)) (interface{}, error) {
	return f(key, data)
}

func (c *noCache) Capacity() int {
	return 0
}
