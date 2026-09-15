package postgres

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Conn is one physical connection to a PostgreSQL server. It is not safe
// for concurrent use — Pool serializes access by handing each caller
// exclusive use of a Conn for the duration of one call.
type Conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
}

// connect dials, completes the startup/auth handshake, and normalizes the
// session's DATESTYLE/TIME ZONE so this driver's timestamp parsing has a
// predictable format to work from.
func connect(ctx context.Context, d dsn) (*Conn, error) {
	if d.SSLMode != "" && d.SSLMode != "disable" {
		return nil, fmt.Errorf(
			"postgres: sslmode=%q requires TLS, which this build does not implement yet "+
				"(see PLAN.md's Pass 3 scope note) — use sslmode=disable for now", d.SSLMode)
	}

	var dialer net.Dialer
	nc, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, fmt.Errorf("postgres: dial: %w", err)
	}

	c := &Conn{
		nc: nc,
		r:  bufio.NewReader(nc),
		w:  bufio.NewWriter(nc),
	}

	if err := c.startup(d); err != nil {
		_ = nc.Close()
		return nil, err
	}
	if err := c.normalizeSession(); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) startup(d dsn) error {
	params := map[string]string{
		"user":            d.User,
		"database":        d.Database,
		"client_encoding": "UTF8",
	}
	if err := writeStartupMessage(c.w, params); err != nil {
		return fmt.Errorf("postgres: sending startup message: %w", err)
	}
	if err := c.w.Flush(); err != nil {
		return err
	}

	for {
		msg, err := readMessage(c.r)
		if err != nil {
			return fmt.Errorf("postgres: reading startup response: %w", err)
		}
		switch msg.Type {
		case msgAuth:
			if err := c.handleAuth(msg.Payload, d); err != nil {
				return err
			}
		case msgParameterStatus, msgBackendKeyData, msgNoticeResponse:
			// not needed for this driver's scope: no cancel-request
			// support, and we pin session settings ourselves below.
		case msgErrorResponse:
			return parseErrorResponse(msg.Payload)
		case msgReadyForQuery:
			return nil
		default:
			return fmt.Errorf("postgres: unexpected message type %q during startup", msg.Type)
		}
	}
}

// handleAuth processes one AuthenticationXXX message, sending a
// PasswordMessage in reply when the server challenges for one. Only
// cleartext (code 3) and MD5 (code 5) are supported — see this package's
// doc comment for why SCRAM-SHA-256 (code 10) is not.
func (c *Conn) handleAuth(payload []byte, d dsn) error {
	if len(payload) < 4 {
		return fmt.Errorf("postgres: malformed authentication message")
	}
	code := int32(binary.BigEndian.Uint32(payload[0:4]))
	switch code {
	case 0: // AuthenticationOk
		return nil
	case 3: // AuthenticationCleartextPassword
		return c.sendPassword(d.Password)
	case 5: // AuthenticationMD5Password
		if len(payload) < 8 {
			return fmt.Errorf("postgres: malformed MD5 authentication message")
		}
		var salt [4]byte
		copy(salt[:], payload[4:8])
		return c.sendPassword(hashMD5Password(d.User, d.Password, salt))
	default:
		return fmt.Errorf(
			"postgres: unsupported authentication method %d — this build supports "+
				"cleartext and MD5 only; SCRAM-SHA-256 is a documented gap (PLAN.md Pass 3)", code)
	}
}

func (c *Conn) sendPassword(password string) error {
	if err := c.writeMessage(msgPassword, appendCString(nil, password)); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Conn) normalizeSession() error {
	if _, err := c.simpleExec(context.Background(), "SET DATESTYLE = 'ISO'"); err != nil {
		return fmt.Errorf("postgres: normalizing session (datestyle): %w", err)
	}
	if _, err := c.simpleExec(context.Background(), "SET TIME ZONE 'UTC'"); err != nil {
		return fmt.Errorf("postgres: normalizing session (time zone): %w", err)
	}
	return nil
}

// Close sends Terminate and closes the underlying TCP connection.
func (c *Conn) Close() error {
	_ = c.writeMessage(msgTerminate, nil)
	_ = c.w.Flush()
	return c.nc.Close()
}

func (c *Conn) writeMessage(typ byte, payload []byte) error {
	return writeMessage(c.w, typ, payload)
}

// withDeadline bounds fn by ctx: a deadline on ctx becomes a socket
// deadline, and ctx's own cancellation (via context.AfterFunc) closes the
// underlying connection outright, unblocking any in-flight Read/Write.
// Either path leaves the Conn unusable afterward — callers must treat any
// error out of withDeadline as "discard this Conn", which Pool.release's
// isHealthy check already does for anything that isn't a *PgError.
func (c *Conn) withDeadline(ctx context.Context, fn func() error) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.nc.SetDeadline(deadline)
		defer c.nc.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { _ = c.nc.Close() })
	defer stop()
	return fn()
}

// simpleExec runs query via the Simple Query protocol ('Q'). Used only
// for statements with no parameters — BEGIN/COMMIT/ROLLBACK, session
// SET commands, and migration scripts — never for anything carrying
// user-supplied values, which always go through executeExtended's real
// parameter binding.
func (c *Conn) simpleExec(ctx context.Context, query string) (string, error) {
	var tag string
	err := c.withDeadline(ctx, func() error {
		if err := c.writeMessage(msgQuery, appendCString(nil, query)); err != nil {
			return err
		}
		if err := c.w.Flush(); err != nil {
			return err
		}
		var pendingErr error
		for {
			msg, err := readMessage(c.r)
			if err != nil {
				return err
			}
			switch msg.Type {
			case msgCommandComplete:
				tag = decodeCString(msg.Payload)
			case msgErrorResponse:
				pendingErr = parseErrorResponse(msg.Payload)
			case msgReadyForQuery:
				return pendingErr
			}
		}
	})
	return tag, err
}

// executeExtended runs query via Parse/Bind/Execute/Sync — the only path
// that safely binds args as real parameters rather than string-
// concatenating them into the SQL text (framework guide §5.4: "never
// string-concatenated SQL"). It buffers the full result set in memory;
// see this package's doc comment for that trade-off.
func (c *Conn) executeExtended(ctx context.Context, query string, args []any) (*resultSet, error) {
	var rs *resultSet
	err := c.withDeadline(ctx, func() error {
		if err := c.writeMessage(msgParse, buildParseMessage(query)); err != nil {
			return err
		}
		bindPayload, err := buildBindMessage(args)
		if err != nil {
			return err
		}
		if err := c.writeMessage(msgBind, bindPayload); err != nil {
			return err
		}
		if err := c.writeMessage(msgExecute, buildExecuteMessage()); err != nil {
			return err
		}
		if err := c.writeMessage(msgSync, nil); err != nil {
			return err
		}
		if err := c.w.Flush(); err != nil {
			return err
		}

		result := &resultSet{}
		var pendingErr error
		for {
			msg, err := readMessage(c.r)
			if err != nil {
				return err
			}
			switch msg.Type {
			case msgDataRow:
				row, err := decodeDataRow(msg.Payload)
				if err != nil {
					return err
				}
				result.rows = append(result.rows, row)
			case msgCommandComplete:
				result.commandTag = decodeCString(msg.Payload)
			case msgErrorResponse:
				pendingErr = parseErrorResponse(msg.Payload)
			case msgReadyForQuery:
				if pendingErr != nil {
					return pendingErr
				}
				rs = result
				return nil
			// msgParseComplete, msgBindComplete, msgNoData,
			// msgRowDescription, msgNoticeResponse, msgParameterStatus:
			// nothing to do with these for this driver's scope.
			default:
			}
		}
	})
	return rs, err
}
