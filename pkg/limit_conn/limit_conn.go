package limitconn

import (
	"context"
	"io"
	"net"
	"time"
)

// TODO: use context base tcp connection read and write instead of CloseConnAggressively
func CloseConnAggressively(conn net.Conn, msg []byte, t time.Duration) {
	conn.SetDeadline(time.Now().Add(t))
	_, _ = conn.Write(msg)
	_ = conn.Close()
}

// Wrapper is NOT thread safe !
type Wrapper struct {
	rawConn    net.Conn
	readLimit  *time.Duration
	writeLimit *time.Duration
	closed     bool
}

var _ io.ReadWriteCloser = (*Wrapper)(nil) // interface compliance check

func defaultCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Minute)
}

func Wrap(rwc net.Conn) *Wrapper {
	return &Wrapper{rawConn: rwc}
}

func (w *Wrapper) SetLimit(d time.Duration) *Wrapper {
	return w.SetReadLimit(d).SetWriteLimit(d)
}

func (w *Wrapper) SetReadLimit(d time.Duration) *Wrapper {
	w.readLimit = &d
	return w
}

func (w *Wrapper) SetWriteLimit(d time.Duration) *Wrapper {
	w.writeLimit = &d
	return w
}

func (w *Wrapper) IsConnTimedout() bool {
	return w.closed
}

func (w *Wrapper) Read(p []byte) (n int, err error) {
	var done chan struct{}
	if w.readLimit != nil {
		timer := time.NewTimer(*w.readLimit)
		done = make(chan struct{}, 1)
		defer close(done)
		go func() {
			select {
			case <-timer.C:
				// time limit exceeded:
				_ = w.rawConn.Close()
				w.closed = true
			case <-done:
				return
			}
		}()
	}

	n, err = w.rawConn.Read(p)
	if done != nil {
		done <- struct{}{}
	}
	return n, err
}

func (w *Wrapper) Write(p []byte) (n int, err error) {
	var done chan struct{}
	if w.writeLimit != nil {
		timer := time.NewTimer(*w.writeLimit)
		done = make(chan struct{}, 1)
		defer close(done)
		go func() {
			select {
			case <-timer.C:
				// time limit exceeded:
				_ = w.rawConn.Close()
				w.closed = true
			case <-done:
				return
			}
		}()
	}

	n, err = w.rawConn.Write(p)
	if done != nil {
		done <- struct{}{}
	}
	return n, err
}

func (w *Wrapper) Close() error {
	w.closed = true
	return w.rawConn.Close()
}
