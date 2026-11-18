package contextutil

import "context"

// A problematic situation when implementing context in a function
// is when that function has more than one return values
// if function has only one return value we can safely wrap it something like this
/*
	func DoSomething() error {}
	ch := make(chan error)
	go func() {
		ch <- DoSomething()
	}()
	select {
	case err := <-ch:
		// handle error
	case <-ctx.Done():
		// handle context cancelation
	}
*/
// but what if we have more than one value to return?
// we can use generics and a struct and that is what we are doing here
// here we use struct and generics to store return values of a function
// instead of storing it in a []interface{}

type twoValueCtx[T1 any, T2 any] struct {
	var1 T1
	var2 T2
}

type threeValueCtx[T1 any, T2 any, T3 any] struct {
	var1 T1
	var2 T2
	var3 T3
}

// ExecFunc implements context for a function which has no return values
// and executes that function. if context is cancelled before function returns
// it will return context error otherwise it will return nil
func ExecFunc(ctx context.Context, fn func()) error {
	ch := make(chan struct{}, 1) // buffered so the worker can send-and-exit if ctx is cancelled first
	go func() {
		fn()
		ch <- struct{}{}
	}()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ExecFuncWithTwoReturns wraps a function which has two return values given that last one is error
// and executes that function in a goroutine there by implementing context
// if context is cancelled before function returns it will return context error
// otherwise it will return function's return values
func ExecFuncWithTwoReturns[T1 any](ctx context.Context, fn func() (T1, error)) (T1, error) {
	ch := make(chan twoValueCtx[T1, error], 1) // buffered so the worker can send-and-exit if ctx is cancelled first
	go func() {
		x, y := fn()
		ch <- twoValueCtx[T1, error]{var1: x, var2: y}
	}()
	select {
	case <-ctx.Done():
		var tmp T1
		return tmp, ctx.Err()
	case v := <-ch:
		return v.var1, v.var2
	}
}

// ExecFuncWithThreeReturns wraps a function which has three return values given that last one is error
// and executes that function in a goroutine there by implementing context
// if context is cancelled before function returns it will return context error
// otherwise it will return function's return values
func ExecFuncWithThreeReturns[T1 any, T2 any](ctx context.Context, fn func() (T1, T2, error)) (T1, T2, error) {
	ch := make(chan threeValueCtx[T1, T2, error], 1) // buffered so the worker can send-and-exit if ctx is cancelled first
	go func() {
		x, y, z := fn()
		ch <- threeValueCtx[T1, T2, error]{var1: x, var2: y, var3: z}
	}()
	select {
	case <-ctx.Done():
		var tmp1 T1
		var tmp2 T2
		return tmp1, tmp2, ctx.Err()
	case v := <-ch:
		return v.var1, v.var2, v.var3
	}
}
