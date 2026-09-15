package postgres

import (
	"context"
	"fmt"
	"sync"

	"struct-framework/internal/platform/store"
)

// Pool is a bounded PostgreSQL connection pool implementing store.Driver.
// Deviation from the framework guide: §7 specifies pgxpool.Pool's exact
// shape (Acquire/Release/Query/Exec/QueryRow/Ping/Close) so a future
// real-pgx swap only touches this package — Pool matches that shape.
type Pool struct {
	dsn dsn
	sem chan struct{}

	mu     sync.Mutex
	idle   []*Conn
	closed bool
}

// Open parses dataSourceName and configures a pool of at most maxConns
// connections. It does not dial anything yet — the first Acquire (from
// Exec/Query/QueryRow/Ping/BeginTx) opens the first real connection, so a
// bad connection string surfaces on first use rather than at Open.
func Open(dataSourceName string, maxConns int) (*Pool, error) {
	if maxConns <= 0 {
		maxConns = 10
	}
	d, err := parseDSN(dataSourceName)
	if err != nil {
		return nil, err
	}
	return &Pool{
		dsn: d,
		sem: make(chan struct{}, maxConns),
	}, nil
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
		return nil, fmt.Errorf("postgres: pool is closed")
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

// release returns conn to the idle list if healthy, otherwise closes it.
// Either way it frees the connection slot so a future Acquire can proceed
// — discarding an unhealthy connection is safe (if wasteful); reusing one
// whose protocol state might be corrupted is not.
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

// isHealthy is deliberately conservative: only a *PgError — a
// well-formed reply from the server — leaves the connection's protocol
// state known-good. Any other error (network failure, a framing error in
// our own message decoding) means that state is unknown, so the
// connection is discarded rather than risked.
func isHealthy(err error) bool {
	if err == nil {
		return true
	}
	_, isPgErr := err.(*PgError)
	return isPgErr
}

func (p *Pool) Exec(ctx context.Context, query string, args ...any) (store.Result, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := conn.executeExtended(ctx, query, args)
	p.release(conn, isHealthy(err))
	if err != nil {
		return nil, err
	}
	return execResult{tag: rs.commandTag}, nil
}

func (p *Pool) Query(ctx context.Context, query string, args ...any) (store.Rows, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := conn.executeExtended(ctx, query, args)
	p.release(conn, isHealthy(err))
	if err != nil {
		return nil, err
	}
	return &rowsImpl{rows: rs.rows}, nil
}

func (p *Pool) QueryRow(ctx context.Context, query string, args ...any) store.Row {
	conn, err := p.acquire(ctx)
	if err != nil {
		return &rowImpl{err: err}
	}
	rs, err := conn.executeExtended(ctx, query, args)
	p.release(conn, isHealthy(err))
	if err != nil {
		return &rowImpl{err: err}
	}
	if len(rs.rows) == 0 {
		return &rowImpl{err: store.ErrNoRows}
	}
	return &rowImpl{row: rs.rows[0]}
}

// Ping is a bounded-timeout liveness check — /readyz (framework guide
// §13) calls this with a short-deadline context so an unreachable
// database fails fast rather than hanging the health check.
func (p *Pool) Ping(ctx context.Context) error {
	_, err := p.Exec(ctx, "SELECT 1")
	return err
}

func (p *Pool) BeginTx(ctx context.Context) (store.Tx, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.simpleExec(ctx, "BEGIN"); err != nil {
		p.release(conn, isHealthy(err))
		return nil, err
	}
	return &txImpl{pool: p, conn: conn}, nil
}

// ExecScript runs sql via the Simple Query protocol, which — unlike
// executeExtended's Parse — accepts multiple ;-separated statements in
// one round trip. It exists solely for trusted, non-parameterized SQL:
// migration scripts. Never pass user-supplied input here.
func (p *Pool) ExecScript(ctx context.Context, sql string) error {
	conn, err := p.acquire(ctx)
	if err != nil {
		return err
	}
	_, err = conn.simpleExec(ctx, sql)
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
	rs, err := t.conn.executeExtended(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return execResult{tag: rs.commandTag}, nil
}

func (t *txImpl) Query(ctx context.Context, query string, args ...any) (store.Rows, error) {
	rs, err := t.conn.executeExtended(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &rowsImpl{rows: rs.rows}, nil
}

func (t *txImpl) QueryRow(ctx context.Context, query string, args ...any) store.Row {
	rs, err := t.conn.executeExtended(ctx, query, args)
	if err != nil {
		return &rowImpl{err: err}
	}
	if len(rs.rows) == 0 {
		return &rowImpl{err: store.ErrNoRows}
	}
	return &rowImpl{row: rs.rows[0]}
}

func (t *txImpl) Ping(ctx context.Context) error {
	_, err := t.conn.executeExtended(ctx, "SELECT 1", nil)
	return err
}

func (t *txImpl) BeginTx(ctx context.Context) (store.Tx, error) {
	return nil, fmt.Errorf("postgres: nested transactions are not supported")
}

// Close on a Tx deliberately does nothing — a transaction's lifecycle
// ends via Commit or Rollback, which are what actually return the
// connection to the pool. This only exists to satisfy store.Driver.
func (t *txImpl) Close() error { return nil }

func (t *txImpl) Commit() error {
	if t.done {
		return fmt.Errorf("postgres: transaction already committed or rolled back")
	}
	t.done = true
	_, err := t.conn.simpleExec(context.Background(), "COMMIT")
	t.pool.release(t.conn, isHealthy(err))
	return err
}

func (t *txImpl) Rollback() error {
	if t.done {
		return fmt.Errorf("postgres: transaction already committed or rolled back")
	}
	t.done = true
	_, err := t.conn.simpleExec(context.Background(), "ROLLBACK")
	t.pool.release(t.conn, isHealthy(err))
	return err
}

var (
	_ store.Driver = (*Pool)(nil)
	_ store.Tx     = (*txImpl)(nil)
)
