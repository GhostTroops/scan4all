// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package value provides runtime utilities for working with generic type
// parameters as payload values in bart data structures.
//
// The package offers three main categories of utilities:
//
// # V as type struct{} Detection
//
// IsEmptyStruct[V] detects whether a type parameter V is a `struct{}`. These
// types carry no information in their values. Omitting them from dumps
// and prints reduces line noise and improves readability.
//
// # Value Equality
//
// The [Equal] function enables custom equality logic for payload values.
// When V implements an `Equal(V) bool` method, [Equal] uses that implementation.
//
// # Value Cloning
//
// The [CloneFnFactory] supports copying of payload values for persistent
// operations. When V implements a `Clone() V` method,
// bart methods like InsertPersist, DeletePersist, and UnionPersist use the
// generated clone function to create independent copies.
//
// This is an internal package used by the bart data structure implementation.
package value

// IsEmptyStruct reports whether type V is the unnamed empty struct type `struct{}`.
func IsEmptyStruct[V any]() bool {
	var zero V
	_, ok := any(zero).(struct{})
	return ok
}

// Equal compares two values of type V for equality.
//
// If V implements an `Equal(V) bool` method, its custom equality logic is used.
// Otherwise, values are compared directly using the == operator.
//
// If V is not comparable at runtime (such as a slice or map without an Equal
// method), a runtime panic will occur.
//
// Note: If V implements Equal(V) bool with a pointer receiver, the Equal
// method should handle nil receivers gracefully.
func Equal[V any](v1, v2 V) bool {
	if eq, ok := any(v1).(interface{ Equal(V) bool }); ok {
		return eq.Equal(v2)
	}

	return any(v1) == any(v2)
}

// CloneFnFactory returns a function that takes a value of type V and returns
// a copy by calling its `Clone` method.
//
// If V does not implement a `Clone() V` method, it returns nil.
//
// Note: If V implements `Clone() V` with a pointer receiver, the `Clone`
// method should handle nil receivers gracefully.
func CloneFnFactory[V any]() func(V) V {
	var zero V

	// Safely check if V implements the clone method using an inline interface.
	if _, ok := any(zero).(interface{ Clone() V }); ok {
		// Return an anonymous closure directly.
		// Since we already proved V implements the interface above,
		// the direct type assertion here is guaranteed to succeed.
		return func(val V) V {
			return any(val).(interface{ Clone() V }).Clone()
		}
	}

	return nil
}
