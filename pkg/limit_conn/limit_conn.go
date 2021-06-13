package limitconn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tls-handshake/pkg/rand"
)

// TODO: use context base tcp connection read and write instead of CloseConnAggressively
func CloseConnAggressively(conn net.Conn, msg []byte, t time.Duration) {
	conn.SetDeadline(time.Now().Add(t))
	_, _ = conn.Write(msg)
	_ = conn.Close()
}

type Wrapper struct {
	rawConn    net.Conn
	conID      string
	readLimit  *time.Duration
	writeLimit *time.Duration
	closed     bool
	mux        sync.Mutex
}

var _ net.Conn = (*Wrapper)(nil) // interface compliance check

func Wrap(conn net.Conn, conID string) *Wrapper {
	if conID == "" {
		conID += rand.GenString(32)
	}
	return &Wrapper{rawConn: conn, conID: conID}
}

func (w *Wrapper) SetLimit(d time.Duration) *Wrapper {
	return w.SetReadLimit(d).SetWriteLimit(d)
}

func (w *Wrapper) SetReadLimit(d time.Duration) *Wrapper {
	w.mux.Lock()
	defer w.mux.Unlock()
	w.readLimit = &d
	return w
}

func (w *Wrapper) SetWriteLimit(d time.Duration) *Wrapper {
	w.mux.Lock()
	defer w.mux.Unlock()
	w.writeLimit = &d
	return w
}

func (w *Wrapper) IsConnClosed() bool {
	w.mux.Lock()
	defer w.mux.Unlock()
	return w.closed
}

func (w *Wrapper) Read(p []byte) (n int, err error) {
	w.mux.Lock()
	defer w.mux.Unlock()
	if w.closed {
		return 0, errors.New("read on closed connection")
	}

	var done chan struct{}
	if w.readLimit != nil {
		timer := time.NewTimer(*w.readLimit)
		done = make(chan struct{}, 1)
		defer close(done)
		go func() {
			select {
			case <-timer.C:
				// time limit exceeded:
				fmt.Println("Connection closed on slow read")
				_ = w.Close()
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
	w.mux.Lock()
	defer w.mux.Unlock()
	if w.closed {
		return 0, errors.New("write on closed connection")
	}

	var done chan struct{}
	if w.writeLimit != nil {
		timer := time.NewTimer(*w.writeLimit)
		done = make(chan struct{}, 1)
		defer close(done)
		go func() {
			select {
			case <-timer.C:
				// time limit exceeded:
				fmt.Println("Connection closed on slow write")
				_ = w.Close()
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
	w.mux.Lock()
	defer w.mux.Unlock()

	if w.closed {
		fmt.Println("calling close on closed conn with id =", w.conID)
		return nil
	}

	w.closed = true
	fmt.Println("closed connection with id =", w.conID)
	return w.rawConn.Close()
}

// Interface compliance functions:

func (w *Wrapper) LocalAddr() net.Addr { return w.rawConn.LocalAddr() }

func (w *Wrapper) RemoteAddr() net.Addr { return w.rawConn.RemoteAddr() }

func (w *Wrapper) SetDeadline(t time.Time) error { return w.rawConn.SetDeadline(t) }

func (w *Wrapper) SetReadDeadline(t time.Time) error { return w.rawConn.SetReadDeadline(t) }

func (w *Wrapper) SetWriteDeadline(t time.Time) error { return w.rawConn.SetWriteDeadline(t) }
