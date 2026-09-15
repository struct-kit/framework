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
			"postgres: sslmode=%q requires TLS, which this build does not implement yet — use sslmode=disable for now", d.SSLMode)
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
// PasswordMessage in reply when the server challenges for one.  Three
// challenge/response protocols are supported:
//   - code 0  AuthenticationOk              — auth complete, return nil
//   - code 3  AuthenticationCleartextPassword — send password plaintext
//   - code 5  AuthenticationMD5Password       — MD5(password, salt, user)
//   - code 10 AuthenticationSASL              — SCRAM-SHA-256 full handshake
//     (drives codes 11 (SASLContinue) and 12 (SASLFinal) internally
//     before returning on AuthenticationOk).
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
	case 10: // AuthenticationSASL — start SCRAM-SHA-256 handshake
		return c.handleSASL(payload[4:], d)
	default:
		return fmt.Errorf(
			"postgres: unsupported authentication method %d — supported: cleartext(3), MD5(5), SCRAM-SHA-256(10)", code)
	}
}

// handleSASL drives the full SCRAM-SHA-256 exchange: pick a mechanism, send
// SASLInitialResponse → SASLContinue/SASLFinal round-trip → verify server
// signature, and finally return when AuthenticationOk.  Any message that
// doesn't match the expected sequence fails the connection with a descriptive
// descriptive error.
func (c *Conn) handleSASL(afterCode10 []byte, d dsn) error {
	mechs, err := parseSASLMechanisms(afterCode10)
	if err != nil {
		return err
	}
	var chosen string
	for _, m := range mechs {
		if m == scramSHA256 {
			chosen = m
			break
		}
	}
	if chosen == "" {
		return fmt.Errorf("postgres: server offered SASL mechanisms %v — this driver only implements %q",
			mechs, scramSHA256)
	}

	// ---- client-first: SASLInitialResponse ----
	gs2AndBare, clientBare, err := scramClientFirst()
	if err != nil {
		return err
	}
	initPayload := buildSASLInitialResponse(chosen, []byte(gs2AndBare))
	if err := c.writeMessage(msgPassword, initPayload); err != nil {
		return fmt.Errorf("postgres: scram: sending SASLInitialResponse: %w", err)
	}
	if err := c.w.Flush(); err != nil {
		return err
	}

	// ---- wait for server-first via AuthenticationSASLContinue (code 11) ----
	respMsg, err := c.nextAuthMessage("SASLContinue")
	if err != nil {
		return err
	}
	serverFirst, err := extractSASLContinueData(respMsg.Payload)
	if err != nil {
		return err
	}
	combinedNonce, salt, iterations, err := scramServerFirst(serverFirst)
	if err != nil {
		return err
	}

	// ---- client-final: SASLResponse ----
	clientFinalWire, expectedServerSig, err := scramClientFinal(
		scramGS2Header, clientBare, combinedNonce, salt, iterations, d.Password,
	)
	if err != nil {
		return err
	}
	if err := c.writeMessage(msgPassword, buildSASLResponse([]byte(clientFinalWire))); err != nil {
		return fmt.Errorf("postgres: scram: sending SASLResponse: %w", err)
	}
	if err := c.w.Flush(); err != nil {
		return err
	}

	// ---- wait for server-final via AuthenticationSASLFinal (code 12) ----
	finalMsg, err := c.nextAuthMessage("SASLFinal")
	if err != nil {
		return err
	}
	serverFinal, err := extractSASLFinalData(finalMsg.Payload)
	if err != nil {
		return err
	}
	if err := scramVerifyServerFinal(serverFinal, expectedServerSig); err != nil {
		return err
	}

	// ---- final AuthenticationOk (code 0) ----
	okMsg, err := c.nextAuthMessage("AuthenticationOk")
	if err != nil {
		return err
	}
	if len(okMsg.Payload) < 4 {
		return fmt.Errorf("postgres: scram: short AuthenticationOk")
	}
	if int32(binary.BigEndian.Uint32(okMsg.Payload[0:4])) != 0 {
		return fmt.Errorf("postgres: scram: expected AuthenticationOk, got code %d",
			int32(binary.BigEndian.Uint32(okMsg.Payload[0:4])))
	}
	return nil
}

// nextAuthMessage reads exactly one backend message, expecting it to be an
// Authentication (type 'R').  Any other message (ErrorResponse, ReadyForQuery,
// …) is surfaced with the supplied label.  Used by handleSASL for the multi-step
// handshake.
func (c *Conn) nextAuthMessage(label string) (rawMessage, error) {
	msg, err := readMessage(c.r)
	if err != nil {
		return rawMessage{}, fmt.Errorf("postgres: scram: reading %s: %w", label, err)
	}
	switch msg.Type {
	case msgAuth:
		return msg, nil
	case msgErrorResponse:
		return rawMessage{}, parseErrorResponse(msg.Payload)
	default:
		return rawMessage{}, fmt.Errorf("postgres: scram: unexpected message %q while waiting for %s", msg.Type, label)
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
