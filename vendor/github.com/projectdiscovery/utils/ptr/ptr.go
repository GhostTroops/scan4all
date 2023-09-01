package ptr

// Safe dereferences safely a pointer
// - if the pointer is nil => returns the zero value of the type of the pointer if nil
// - if the pointer is not nil => returns the dereferenced pointer
func Safe[T any](v *T) T {
	if v == nil {
		return *new(T)
	}
	return *v
}
