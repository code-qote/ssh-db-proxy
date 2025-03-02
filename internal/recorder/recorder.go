package recorder

import (
	"fmt"
	"sync"

	"github.com/jackc/pgproto3/v2"
)

type Recorder interface {
	WriteFrontendMessage(msg pgproto3.FrontendMessage) error
	WriteBackendMessage(msg pgproto3.BackendMessage) error
	Save() error
}

type message struct {
	from    string
	msgType string
}

type StdoutRecorder struct {
	mu       sync.Mutex
	messages []message
}

func (r *StdoutRecorder) WriteFrontendMessage(msg pgproto3.FrontendMessage) error {
	r.mu.Lock()
	r.messages = append(r.messages, message{from: "client", msgType: fmt.Sprintf("%T", msg)})
	r.mu.Unlock()
	return nil
}

func (r *StdoutRecorder) WriteBackendMessage(msg pgproto3.BackendMessage) error {
	r.mu.Lock()
	r.messages = append(r.messages, message{from: "server", msgType: fmt.Sprintf("%T", msg)})
	r.mu.Unlock()
	return nil
}

func (r *StdoutRecorder) Save() error {
	r.mu.Lock()
	fmt.Println(r.messages)
	r.mu.Unlock()
	return nil
}
