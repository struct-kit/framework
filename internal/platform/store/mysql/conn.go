package mysql

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"
)

// Conn is one physical connection to a MySQL server. Not safe for
// concurrent use — Pool serializes access, matching the postgres
// package's Conn/Pool split.
type Conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
}

func connect(ctx context.Context, d dsn) (*Conn, error) {
	var dialer net.Dialer
	nc, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, fmt.Errorf("mysql: dial: %w", err)
	}

	c := &Conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	if err := c.handshake(d); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) handshake(d dsn) error {
	pkt, err := readPacket(c.r)
	if err != nil {
		return fmt.Errorf("mysql: reading initial handshake: %w", err)
	}
	if len(pkt.Payload) > 0 && pkt.Payload[0] == headerErr {
		if mysqlErr, perr := parseErrPacket(pkt.Payload); perr == nil {
			return mysqlErr
		}
		return fmt.Errorf("mysql: server rejected the connection before handshake")
	}

	hs, err := parseInitialHandshake(pkt.Payload)
	if err != nil {
		return err
	}
	if hs.AuthPluginName != "" && hs.AuthPluginName != "mysql_native_password" {
		return fmt.Errorf(
			"mysql: server requires auth plugin %q — this build only supports "+
				"mysql_native_password (see this package's doc comment for the gap)", hs.AuthPluginName)
	}

	authResponse := scrambleNativePassword(d.Password, hs.AuthPluginData)
	caps := clientCapabilities(true) // always send a database name
	responsePayload := buildHandshakeResponse(caps, d.User, d.Database, authResponse)

	if err := writePacket(c.w, pkt.Sequence+1, responsePayload); err != nil {
		return err
	}
	if err := c.w.Flush(); err != nil {
		return err
	}

	resultPkt, err := readPacket(c.r)
	if err != nil {
		return fmt.Errorf("mysql: reading authentication result: %w", err)
	}
	return checkAuthResult(resultPkt.Payload)
}

func checkAuthResult(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("mysql: empty authentication result packet")
	}
	switch payload[0] {
	case headerOK:
		return nil
	case headerErr:
		mysqlErr, err := parseErrPacket(payload)
		if err != nil {
			return fmt.Errorf("mysql: authentication failed (and the error packet itself was unparseable)")
		}
		return mysqlErr
	case 0xfe: // AuthSwitchRequest — same leading byte as an EOF packet, unambiguous here by protocol state
		return fmt.Errorf(
			"mysql: server requested a different auth method — this build only supports " +
				"mysql_native_password (see this package's doc comment for the gap)")
	case 0x01: // AuthMoreData — the caching_sha2_password full-auth exchange
		return fmt.Errorf(
			"mysql: server sent AuthMoreData (likely caching_sha2_password) — " +
				"this build only supports mysql_native_password")
	default:
		return fmt.Errorf("mysql: unexpected authentication result packet header 0x%x", payload[0])
	}
}

// Close sends COM_QUIT and closes the underlying TCP connection.
func (c *Conn) Close() error {
	_ = writePacket(c.w, 0, []byte{comQuit})
	_ = c.w.Flush()
	return c.nc.Close()
}

// withDeadline mirrors the postgres package's Conn.withDeadline exactly:
// a ctx deadline becomes a socket deadline, and ctx cancellation closes
// the connection outright via context.AfterFunc. Either path leaves the
// Conn unusable afterward — Pool.release's isHealthy check handles that.
func (c *Conn) withDeadline(ctx context.Context, fn func() error) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.nc.SetDeadline(deadline)
		defer c.nc.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { _ = c.nc.Close() })
	defer stop()
	return fn()
}
