package mysql

import (
	"context"
	"fmt"
	"sync"

	"struct-framework/internal/platform/store"
)

// Pool is a bounded MySQL connection pool implementing store.Driver —
// the same shape as the postgres package's Pool, so callers never care
// which dialect they're holding.
type Pool struct {
	dsn dsn
	sem chan struct{}

	mu     sync.Mutex
	idle   []*Conn
	closed bool
}

func Open(dataSourceName string, maxConns int) (*Pool, error) {
	if maxConns <= 0 {
		maxConns = 10
	}
	d, err := parseDSN(dataSourceName)
	if err != nil {
		return nil, err
	}
	return &Pool{dsn: d, sem: make(chan struct{}, maxConns)}, nil
}

func (p *Pool) acquire(ctx context.Context) (*Conn, error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.sem
		return nil, fmt.Errorf("mysql: pool is closed")
	}
	if n := len(p.idle); n > 0 {
		conn := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()

	conn, err := connect(ctx, p.dsn)
	if err != nil {
		<-p.sem
		return nil, err
	}
	return conn, nil
}

func (p *Pool) release(conn *Conn, healthy bool) {
	if healthy {
		p.mu.Lock()
		if !p.closed {
			p.idle = append(p.idle, conn)
			p.mu.Unlock()
			<-p.sem
			return
		}
		p.mu.Unlock()
	}
	_ = conn.Close()
	<-p.sem
}

// isHealthy mirrors the postgres package's: only a *MySQLError — a
// well-formed reply from the server — leaves the connection's protocol
// state known-good. Anything else means that state is unknown, so the
// connection is discarded.
func isHealthy(err error) bool {
	if err == nil {
		return true
	}
	_, isMySQLErr := err.(*MySQLError)
	return isMySQLErr
}

// runOnConn prepares, executes, and closes a statement in one round trip
// — the binary protocol is the only path parameters take (never the text
// protocol, which would mean string-concatenating them).
func runOnConn(ctx context.Context, conn *Conn, query string, args []any) (*mysqlResultSet, error) {
	stmt, err := conn.prepareStatement(ctx, query)
	if err != nil {
		return nil, err
	}
	rs, err := conn.executeStatement(ctx, stmt, args)
	_ = conn.closeStatement(ctx, stmt) // best-effort — a failed close doesn't invalidate a result already read
	return rs, err
}

func (p *Pool) runQuery(ctx context.Context, query string, args []any) (*mysqlResultSet, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := runOnConn(ctx, conn, query, args)
	p.release(conn, isHealthy(err))
	return rs, err
}

func (p *Pool) Exec(ctx context.Context, query string, args ...any) (store.Result, error) {
	rs, err := p.runQuery(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return execResult{affectedRows: rs.affectedRows}, nil
}

func (p *Pool) Query(ctx context.Context, query string, args ...any) (store.Rows, error) {
	rs, err := p.runQuery(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &rowsImpl{rows: rs.rows}, nil
}

func (p *Pool) QueryRow(ctx context.Context, query string, args ...any) store.Row {
	rs, err := p.runQuery(ctx, query, args)
	if err != nil {
		return &rowImpl{err: err}
	}
	if len(rs.rows) == 0 {
		return &rowImpl{err: store.ErrNoRows}
	}
	return &rowImpl{row: rs.rows[0]}
}

// Ping is a bounded-timeout liveness check — /readyz calls this with a
// short-deadline context so an unreachable database fails fast.
func (p *Pool) Ping(ctx context.Context) error {
	_, err := p.Exec(ctx, "SELECT 1")
	return err
}

func (p *Pool) BeginTx(ctx context.Context) (store.Tx, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.executeText(ctx, "BEGIN"); err != nil {
		p.release(conn, isHealthy(err))
		return nil, err
	}
	return &txImpl{pool: p, conn: conn}, nil
}

// ExecScript runs sql via the text protocol (COM_QUERY, with
// CLIENT_MULTI_STATEMENTS set), for trusted, non-parameterized SQL
// only — migration scripts. Never pass user-supplied input here.
func (p *Pool) ExecScript(ctx context.Context, sql string) error {
	conn, err := p.acquire(ctx)
	if err != nil {
		return err
	}
	err = conn.executeText(ctx, sql)
	p.release(conn, isHealthy(err))
	return err
}

func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, c := range idle {
		_ = c.Close()
	}
	return nil
}

// txImpl is a store.Tx bound to one checked-out Conn for its whole
// lifetime — Commit/Rollback are what returns that Conn to the pool.
type txImpl struct {
	pool *Pool
	conn *Conn
	done bool
}

func (t *txImpl) Exec(ctx context.Context, query string, args ...any) (store.Result, error) {
	rs, err := runOnConn(ctx, t.conn, query, args)
	if err != nil {
		return nil, err
	}
	return execResult{affectedRows: rs.affectedRows}, nil
}

func (t *txImpl) Query(ctx context.Context, query string, args ...any) (store.Rows, error) {
	rs, err := runOnConn(ctx, t.conn, query, args)
	if err != nil {
		return nil, err
	}
	return &rowsImpl{rows: rs.rows}, nil
}

func (t *txImpl) QueryRow(ctx context.Context, query string, args ...any) store.Row {
	rs, err := runOnConn(ctx, t.conn, query, args)
	if err != nil {
		return &rowImpl{err: err}
	}
	if len(rs.rows) == 0 {
		return &rowImpl{err: store.ErrNoRows}
	}
	return &rowImpl{row: rs.rows[0]}
}

func (t *txImpl) Ping(ctx context.Context) error {
	_, err := runOnConn(ctx, t.conn, "SELECT 1", nil)
	return err
}

func (t *txImpl) BeginTx(ctx context.Context) (store.Tx, error) {
	return nil, fmt.Errorf("mysql: nested transactions are not supported")
}

// Close on a Tx deliberately does nothing — a transaction's lifecycle
// ends via Commit or Rollback, which are what actually return the
// connection to the pool. This only exists to satisfy store.Driver.
func (t *txImpl) Close() error { return nil }

func (t *txImpl) Commit() error {
	if t.done {
		return fmt.Errorf("mysql: transaction already committed or rolled back")
	}
	t.done = true
	err := t.conn.executeText(context.Background(), "COMMIT")
	t.pool.release(t.conn, isHealthy(err))
	return err
}

func (t *txImpl) Rollback() error {
	if t.done {
		return fmt.Errorf("mysql: transaction already committed or rolled back")
	}
	t.done = true
	err := t.conn.executeText(context.Background(), "ROLLBACK")
	t.pool.release(t.conn, isHealthy(err))
	return err
}

var (
	_ store.Driver = (*Pool)(nil)
	_ store.Tx     = (*txImpl)(nil)
)
