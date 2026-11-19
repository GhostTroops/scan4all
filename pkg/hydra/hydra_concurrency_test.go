package hydra

import (
	"sync"
	"testing"
)

func TestNewCrackerKeepsSharedAuthListsImmutable(t *testing.T) {
	oldDefaults, oldCustom := DefaultAuthMap, CustomAuthMap
	t.Cleanup(func() {
		DefaultAuthMap, CustomAuthMap = oldDefaults, oldCustom
	})

	DefaultAuthMap = map[string]*AuthList{
		"ssh": {Username: []string{"default-user"}, Password: []string{"default-pass"}},
	}
	CustomAuthMap = &AuthList{Username: []string{"custom-user"}, Password: []string{"custom-pass"}}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cracker := NewCracker(NewAuthInfo("127.0.0.1", 22, "ssh"), true, 1)
			if got, want := cracker.authList.Length(), 4; got != want {
				errs <- got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for got := range errs {
		t.Errorf("cracker auth list length = %d, want 4", got)
	}

	if got := DefaultAuthMap["ssh"].Length(); got != 1 {
		t.Errorf("shared default auth list length = %d, want 1", got)
	}
}
