package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/tls-handshake/internal"
)

const (
	address = "127.0.0.2"
	port    = 8082
)

func Test_e2e_SingleClient(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	go func ()  {
		// don't wait for the server to stop, because it runs forever right now.
		var srv internal.Server
		if err := srv.Listen(address, port); err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(time.Millisecond * 2) // client needs to wait for server to start listening

	go func ()  {
		defer wg.Done()

		var client internal.Client
		if err := client.Connect(address, port); err != nil {
			t.Error(err)
		}
		if err := client.Ping(); err != nil {
			t.Error(err)
		}

		client.Disconnect()
		time.Sleep(time.Millisecond * 2) // wait a bit, to see if the server errors on Disconnect
	}()

	wg.Wait()
}