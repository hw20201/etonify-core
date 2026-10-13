// Package etonifydesktop owns the version-one desktop runtime wire contract.
// It contains no native transport, service, or runtime implementation.
package etonifydesktop

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const ProtocolVersion = 1
const MaximumBodyLength = 16 * 1024 * 1024

type RuntimeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RuntimeEnvelope struct {
	Version           int             `json:"version"`
	Kind              string          `json:"kind"`
	ID                string          `json:"id"`
	SessionID         string          `json:"sessionId"`
	ConfigGeneration  int64           `json:"configGeneration"`
	NetworkGeneration int64           `json:"networkGeneration"`
	Method            string          `json:"method"`
	Payload           json.RawMessage `json:"payload,omitempty"`
	Error             *RuntimeError   `json:"error,omitempty"`
}

// Request and Event share the envelope shape. Kind validation stays at the wire boundary.
type Request = RuntimeEnvelope
type Event = RuntimeEnvelope

func (e RuntimeEnvelope) Validate() error {
	if e.Version != ProtocolVersion {
		return errors.New("unsupported protocol version")
	}
	if e.Kind != "request" && e.Kind != "response" && e.Kind != "event" {
		return errors.New("invalid envelope kind")
	}
	if e.ConfigGeneration < 0 || e.NetworkGeneration < 0 {
		return errors.New("negative generation")
	}
	if e.Error != nil {
		if e.Kind != "response" || len(e.Payload) != 0 {
			return errors.New("error replaces response payload")
		}
	} else if len(e.Payload) == 0 || !json.Valid(e.Payload) || !utf8.Valid(e.Payload) {
		return errors.New("missing or invalid payload")
	}
	return nil
}

func (e *RuntimeEnvelope) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("expected envelope object")
	}
	for _, key := range []string{"version", "kind", "id", "sessionId", "configGeneration", "networkGeneration", "method"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing %s", key)
		}
	}
	type plain RuntimeEnvelope
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	_, hasPayload := fields["payload"]
	_, hasError := fields["error"]
	if hasError == hasPayload {
		return errors.New("expected payload or error")
	}
	if hasError {
		var errorFields map[string]json.RawMessage
		if err := json.Unmarshal(fields["error"], &errorFields); err != nil {
			return err
		}
		for _, key := range []string{"code", "message"} {
			raw, ok := errorFields[key]
			if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("missing error %s", key)
			}
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return err
			}
		}
	}
	if err := RuntimeEnvelope(value).Validate(); err != nil {
		return err
	}
	*e = RuntimeEnvelope(value)
	return nil
}

type Modes struct {
	TunEnabled         bool     `json:"tunEnabled"`
	SystemProxyEnabled bool     `json:"systemProxyEnabled"`
	LaunchAtLogin      bool     `json:"launchAtLogin"`
	LaunchMinimized    bool     `json:"launchMinimized"`
	ConnectOnLaunch    bool     `json:"connectOnLaunch"`
	ProcessRoutingMode string   `json:"processRoutingMode"`
	ProcessPaths       []string `json:"processPaths"`
}

func DefaultModes() Modes {
	return Modes{LaunchMinimized: true, ProcessRoutingMode: "allExceptSelected", ProcessPaths: []string{}}
}

func (m *Modes) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("expected modes object")
	}
	for _, key := range []string{"tunEnabled", "systemProxyEnabled", "launchAtLogin", "launchMinimized", "connectOnLaunch", "processRoutingMode", "processPaths"} {
		if raw, exists := fields[key]; exists && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("null modes %s", key)
		}
	}
	if raw, exists := fields["processPaths"]; exists {
		var paths []json.RawMessage
		if err := json.Unmarshal(raw, &paths); err != nil {
			return err
		}
		for index, path := range paths {
			if bytes.Equal(bytes.TrimSpace(path), []byte("null")) {
				return fmt.Errorf("null process path %d", index)
			}
		}
	}
	type plain Modes
	value := plain(DefaultModes())
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.ProcessRoutingMode != "allExceptSelected" && value.ProcessRoutingMode != "onlySelected" {
		return errors.New("invalid process routing mode")
	}
	*m = Modes(value)
	return nil
}

type StartRequest struct {
	Config            string `json:"config"`
	Modes             Modes  `json:"modes"`
	SessionID         string `json:"sessionId"`
	ConfigGeneration  int64  `json:"configGeneration"`
	NetworkGeneration int64  `json:"networkGeneration"`
}

type Capabilities struct {
	LocalProxy     bool `json:"localProxy"`
	Tun            bool `json:"tun"`
	ProcessRouting bool `json:"processRouting"`
	SystemProxy    bool `json:"systemProxy"`
}

func (c Capabilities) Supports(name string) bool {
	switch name {
	case "localProxy":
		return c.LocalProxy
	case "tun":
		return c.Tun
	case "processRouting":
		return c.ProcessRouting
	case "systemProxy":
		return c.SystemProxy
	default:
		return false
	}
}

type Snapshot struct {
	SessionID         string        `json:"sessionId"`
	ConfigGeneration  int64         `json:"configGeneration"`
	NetworkGeneration int64         `json:"networkGeneration"`
	Phase             string        `json:"phase"`
	Modes             Modes         `json:"modes"`
	SelectedTag       string        `json:"selectedTag"`
	CoreVersion       string        `json:"coreVersion"`
	DaemonAPIVersion  int64         `json:"daemonApiVersion"`
	ServiceVersion    string        `json:"serviceVersion"`
	Capabilities      Capabilities  `json:"capabilities"`
	Error             *RuntimeError `json:"error,omitempty"`
}

// EncodeFrame recursively sorts JSON object keys for a shared Dart/Go corpus.
func EncodeFrame(e RuntimeEnvelope) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&object); err != nil {
		return nil, err
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(object); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(body.Bytes(), []byte{'\n'})
	if len(encoded) > MaximumBodyLength {
		return nil, errors.New("desktop frame exceeds 16 MiB")
	}
	frame := make([]byte, 4+len(encoded))
	binary.LittleEndian.PutUint32(frame, uint32(len(encoded)))
	copy(frame[4:], encoded)
	return frame, nil
}

type FrameDecoder struct {
	reader   io.Reader
	terminal error
}

func NewFrameDecoder(reader io.Reader) *FrameDecoder { return &FrameDecoder{reader: reader} }

// Next rejects oversized lengths before body allocation; any error is terminal.
func (d *FrameDecoder) Next() (RuntimeEnvelope, error) {
	if d.terminal != nil {
		return RuntimeEnvelope{}, d.terminal
	}
	result, err := d.next()
	if err != nil {
		d.terminal = err
	}
	return result, err
}

func (d *FrameDecoder) next() (RuntimeEnvelope, error) {
	var header [4]byte
	if _, err := io.ReadFull(d.reader, header[:]); err != nil {
		return RuntimeEnvelope{}, err
	}
	length := binary.LittleEndian.Uint32(header[:])
	if length == 0 || length > MaximumBodyLength {
		return RuntimeEnvelope{}, errors.New("invalid desktop frame length")
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(d.reader, body); err != nil {
		return RuntimeEnvelope{}, err
	}
	var e RuntimeEnvelope
	if err := json.Unmarshal(body, &e); err != nil {
		return RuntimeEnvelope{}, err
	}
	return e, nil
}
