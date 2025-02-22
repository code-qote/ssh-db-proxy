package recorder

import (
	"fmt"
	"sync"

	"github.com/jackc/pgproto3/v2"
)

type message struct {
	from    string
	msgType string
}

type Recorder struct {
	mu       sync.Mutex
	messages []message
}

func (r *Recorder) WriteFrontendMessage(msg pgproto3.FrontendMessage) {
	r.mu.Lock()
	r.messages = append(r.messages, message{from: "client", msgType: fmt.Sprintf("%T", msg)})
	r.mu.Unlock()
}

func (r *Recorder) WriteBackendMessage(msg pgproto3.BackendMessage) {
	r.mu.Lock()
	r.messages = append(r.messages, message{from: "server", msgType: fmt.Sprintf("%T", msg)})
	r.mu.Unlock()
}

func (r *Recorder) Save() {
	r.mu.Lock()
	fmt.Println(r.messages)
	r.mu.Unlock()
}
