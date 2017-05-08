package typesocket

import (
	"encoding/json"
	"reflect"
)

type Mux map[string]*muxEntry

type muxEntry struct {
	fn      reflect.Value
	argType reflect.Type
}

// NewMux creates a new mux from the given handlers.
// The key in the handlers map is a message ID and the
// interface{} value must be of type func(Conn, T) for
// some type T.
func NewMux(handlers map[string]interface{}) Mux {
	mux := make(map[string]*muxEntry)
	for k, fn := range handlers {
		ty := reflect.TypeOf(fn)
		mux[k] = &muxEntry{
			fn:      reflect.ValueOf(fn),
			argType: ty.In(1),
		}
	}
	return Mux(mux)
}

type envelope struct {
	ID      string
	Message json.RawMessage
}

func encodeMessage(msgID string, v interface{}) ([]byte, error) {
	rawMsg, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	e := &envelope{
		ID:      msgID,
		Message: rawMsg,
	}
	msgBytes, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return msgBytes, nil
}

func (m Mux) openEnvelope(conn Conn, e *envelope) {
	h := m[e.ID]
	if h == nil {
		return
	}

	arg := reflect.New(h.argType)
	if err := json.Unmarshal(e.Message, arg.Interface()); err != nil {
		return
	}

	h.fn.Call([]reflect.Value{reflect.ValueOf(conn), arg.Elem()})
}
