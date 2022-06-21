package go_ora

import "context"

type Transaction struct {
	conn *Connection
	ctx  context.Context
}

func (tx *Transaction) Commit() error {
	tx.conn.autoCommit = true
	tx.conn.session.ResetBuffer()
	tx.conn.session.StartContext(tx.ctx)
	defer tx.conn.session.EndContext()
	return (&simpleObject{connection: tx.conn, operationID: 0xE}).write().read()
}

func (tx *Transaction) Rollback() error {
	tx.conn.autoCommit = true
	tx.conn.session.ResetBuffer()
	tx.conn.session.StartContext(tx.ctx)
	defer tx.conn.session.EndContext()
	return (&simpleObject{connection: tx.conn, operationID: 0xF}).write().read()
}
