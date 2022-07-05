// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import "context"

// Question represents a bootstrap query.
//
//  question := &bootstrap.Question{
//    RegistryType: bootstrap.DNS,
//    Query: "example.cz",
//  }
type Question struct {
	// Bootstrap registry to query.
	RegistryType

	// Query text.
	Query string

	ctx context.Context
}

// WithContext returns a copy of the Question, with context |ctx|.
func (q *Question) WithContext(ctx context.Context) *Question {
	q2 := new(Question)
	*q2 = *q
	q2.ctx = ctx

	return q2
}

// Context returns the Question's context.
//
// The returned context is always non-nil; it defaults to the background context.
func (q *Question) Context() context.Context {
	if q.ctx == nil {
		return context.Background()
	}

	return q.ctx
}
