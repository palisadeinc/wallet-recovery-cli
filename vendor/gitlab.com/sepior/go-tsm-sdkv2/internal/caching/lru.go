package caching

import (
	"container/list"
)

type lru struct {
	maxEntries int
	list       *list.List
	items      map[interface{}]*list.Element
}

type item struct {
	key   interface{}
	value interface{}
}

func newLRU(maxEntries int) *lru {
	return &lru{
		maxEntries: maxEntries,
		list:       list.New(),
		items:      make(map[interface{}]*list.Element, maxEntries+1),
	}
}

func (lru *lru) Get(k interface{}) (interface{}, bool) {
	if i, ok := lru.items[k]; ok {
		lru.list.MoveToFront(i)
		return i.Value.(*item).value, true
	}
	return nil, false
}

func (lru *lru) Set(k, v interface{}) {
	if i, ok := lru.items[k]; ok {
		lru.list.MoveToFront(i)
		i.Value.(*item).value = v
		return
	}
	i := &item{
		key:   k,
		value: v,
	}
	li := lru.list.PushFront(i)
	lru.items[k] = li
	if lru.list.Len() > lru.maxEntries {
		lru.prune()
	}
}
func (lru *lru) Capacity() int {
	return lru.maxEntries
}

func (lru *lru) prune() {
	if li := lru.list.Back(); li != nil {
		lru.list.Remove(li)
		delete(lru.items, li.Value.(*item).key)
	}
}

func (lru *lru) Len() int {
	return lru.list.Len()
}
