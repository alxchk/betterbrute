package main

import (
	"reflect"
	"sync"
)

type (
	clientId uint

	ReplayStorage struct {
		operating bool
		storage   []interface{}
		iterator  chan<- <-chan interface{}

		clients []chan int

		storage_lock *sync.RWMutex
		clients_lock *sync.RWMutex
	}
)

func NewReplayStorage() *ReplayStorage {
	return &ReplayStorage{
		operating:    true,
		storage_lock: new(sync.RWMutex),
		clients_lock: new(sync.RWMutex),
	}
}

func (r *ReplayStorage) push(end int) {
	r.clients_lock.RLock()
	for idx, c := range r.clients {
		log.Debug("[R] Update end: ", idx, "/", len(r.clients))
		c <- end
	}
	r.clients_lock.RUnlock()
}

func (r *ReplayStorage) Add(values ...interface{}) {
	if !r.operating {
		log.Debug("Adding to queue which is closed")
		return
	}

	r.storage_lock.Lock()
	r.storage = append(r.storage, values...)
	end := len(r.storage)
	r.storage_lock.Unlock()
	r.push(end)
}

func (r *ReplayStorage) AddUniq(values ...interface{}) bool {
	if !r.operating || len(values) == 0 {
		return false
	}

	log.Debug("[*] AddUniq - 1")

	new_values := values[:]

	length := len(new_values) - 1
	for i := 0; i < length; i++ {
		for j := i + 1; j <= length; j++ {
			if reflect.DeepEqual(new_values[i], new_values[j]) {
				new_values[j] = new_values[length]
				new_values = new_values[0:length]
				length--
				j--
			}
		}
	}

	if len(new_values) == 0 {
		return false
	}

	r.storage_lock.Lock()

	log.Debug("[*] AddUniq - 2")

	for _, v := range r.storage {
		for idx, y := range new_values {
			if reflect.DeepEqual(y, v) {
				new_values = append(new_values[:idx], new_values[idx+1:]...)
				break
			}
		}
	}

	log.Debug("[*] AddUniq - 3")

	if len(new_values) > 0 {
		r.storage = append(r.storage, new_values...)
		end := len(r.storage)
		log.Debug("[*] AddUniq - 4: Add items: ")
		r.storage_lock.Unlock()
		r.push(end)
		log.Debug("[*] AddUniq - 5")
		return true
	} else {
		r.storage_lock.Unlock()
		log.Debug("[*] AddUniq - 6")
		return false
	}
}

func (r *ReplayStorage) Iterator() <-chan interface{} {
	if !r.operating {
		return nil
	}

	in := make(chan int)
	out := make(chan interface{})

	/* Make shared state */
	r.clients_lock.Lock()
	r.clients = append(r.clients, in)
	end := len(r.storage)
	r.clients_lock.Unlock()

	go func() {
		var value interface{}

		default_out := out
		current_idx := 0
		current_end := end
		current_out := out

		if current_idx == current_end {
			current_out = nil
		}

		report_empty := false

	mainloop:
		for {
			select {
			case current_end, ok := <-in:
				if !ok {
					if current_out == nil {
						break mainloop
					} else {
						continue
					}
				}

				log.Debug("[R] New storage end: ", current_idx, "/", current_end)
				if (current_out == nil || report_empty) && current_idx < current_end {
					log.Debug("[R] Reenable output")
					current_out = default_out
					r.storage_lock.RLock()
					value = r.storage[current_idx]
					r.storage_lock.RUnlock()
					report_empty = false
				}

			case current_out <- value:
				if report_empty {
					current_out = nil
					report_empty = false
				} else {
					current_idx++

					if current_idx >= current_end {
						log.Debug("[R] Disable output: ", current_idx, "/", current_end)
						value = nil
						report_empty = true
					} else {
						r.storage_lock.RLock()
						value = r.storage[current_idx]
						r.storage_lock.RUnlock()
					}
				}
			}
		}

		log.Warning("[R] Iterator complete")
		close(default_out)
	}()

	return out
}

func (r *ReplayStorage) Close() {
	r.operating = false
	r.clients_lock.Lock()
	for _, c := range r.clients {
		close(c)
	}
	r.clients_lock.Unlock()
}
