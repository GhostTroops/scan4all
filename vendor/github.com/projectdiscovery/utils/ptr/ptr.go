package ptr

// Safe dereferences safely a pointer
// - if the pointer is nil => returns the zero value of the type of the pointer if nil
// - if the pointer is not nil => returns the dereferenced pointer
//
// Example:
//
//	var v *int
//	var x = ptr.Safe(v)
func Safe[T any](v *T) T {
	if v == nil {
		return *new(T)
	}
	return *v
}

// Of returns pointer of a given generic type
//
// Example:
//
//	var v int
//	var p = ptr.Of(v)
func Of[T any](v T) *T {
	return &v
}

// When returns pointer of a given generic type
// - if the condition is false => returns nil
// - if the condition is true => returns pointer of the value
//
// Example:
//
//	var v bool
//	var p = ptr.When(v, v != false)
func When[T any](v T, condition bool) *T {
	if !condition {
		return nil
	}
	return &v
}
