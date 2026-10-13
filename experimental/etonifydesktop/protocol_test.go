package etonifydesktop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestProtocolModesDefaults(t *testing.T) {
	var modes Modes
	if err := json.Unmarshal([]byte(`{}`), &modes); err != nil {
		t.Fatal(err)
	}
	if !modes.LaunchMinimized || modes.TunEnabled || modes.SystemProxyEnabled ||
		modes.LaunchAtLogin || modes.ConnectOnLaunch || modes.ProcessRoutingMode != "allExceptSelected" ||
		modes.ProcessPaths == nil || len(modes.ProcessPaths) != 0 {
		t.Fatalf("defaults differ from Dart/schema: %+v", modes)
	}
	for _, bad := range []string{`{"tunEnabled":null}`, `{"processPaths":null}`, `{"processPaths":[null]}`, `{"processPaths":["C:\\Apps\\a.exe",null]}`, `{"processRoutingMode":"invalid"}`} {
		if err := json.Unmarshal([]byte(bad), &modes); err == nil {
			t.Fatalf("accepted invalid modes %s", bad)
		}
	}
}

func TestProtocolCorpus(t *testing.T) {
	data, err := os.ReadFile("fixtures/envelopes.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Envelope json.RawMessage `json:"envelope"`
		FrameHex string          `json:"frameHex"`
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus {
		var want RuntimeEnvelope
		if err := json.Unmarshal(item.Envelope, &want); err != nil {
			t.Fatal(err)
		}
		frame, err := EncodeFrame(want)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(item.FrameHex)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, expected) {
			t.Fatalf("frame differs: %x != %x", frame, expected)
		}
		got, err := NewFrameDecoder(oneByteReader{bytes.NewReader(frame)}).Next()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeFrame(got)
		if err != nil || !bytes.Equal(encoded, expected) {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestProtocolRejectMalformed(t *testing.T) {
	base := `{"version":1,"kind":"request","id":"1","sessionId":"s","configGeneration":0,"networkGeneration":0,"method":"start","payload":null}`
	for _, invalid := range []string{
		`"version":2`, `"version":1.0`, `"version":"1"`,
		`"configGeneration":-1`, `"configGeneration":0.5`, `"configGeneration":9223372036854775808`,
		`"networkGeneration":"0"`, `"kind":"invalid"`, `"sessionId":null`,
	} {
		var entry map[string]json.RawMessage
		_ = json.Unmarshal([]byte("{"+invalid+"}"), &entry)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal([]byte(base), &fields)
		for key, value := range entry {
			fields[key] = value
		}
		data, _ := json.Marshal(fields)
		var envelope RuntimeEnvelope
		if json.Unmarshal(data, &envelope) == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	for _, frame := range [][]byte{{1}, {4, 0, 0, 0, '{'}, {1, 0, 0, 1}, {1, 0, 0, 0, 255}, {1, 0, 0, 0, '{'}, {0, 0, 0, 0}} {
		decoder := NewFrameDecoder(bytes.NewReader(frame))
		if _, err := decoder.Next(); err == nil {
			t.Fatalf("accepted %x", frame)
		}
		if _, err := decoder.Next(); err == nil {
			t.Fatal("decoder resynced after error")
		}
	}
}

func TestProtocolPayloadModels(t *testing.T) {
	start := StartRequest{Config: "{}", Modes: Modes{TunEnabled: true, ProcessRoutingMode: "onlySelected", ProcessPaths: []string{"C:\\Apps\\a.exe"}}, SessionID: "s", ConfigGeneration: 3, NetworkGeneration: 4}
	data, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	for _, key := range []string{"config", "modes", "sessionId", "configGeneration", "networkGeneration"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing %s", key)
		}
	}
	var roundtrip StartRequest
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !roundtrip.Modes.TunEnabled || roundtrip.NetworkGeneration != 4 {
		t.Fatalf("wrong start: %+v", roundtrip)
	}
	if (Capabilities{LocalProxy: true}).Supports("future") {
		t.Fatal("unknown capability supported")
	}
}

func TestProtocolCannotResyncIntoTrailingFrame(t *testing.T) {
	valid, err := EncodeFrame(RuntimeEnvelope{Version: 1, Kind: "response", ID: "same", SessionID: "s", Method: "status", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewFrameDecoder(bytes.NewReader(append([]byte{0, 0, 0, 0}, valid...)))
	_, first := decoder.Next()
	_, second := decoder.Next()
	if first == nil || second != first {
		t.Fatalf("terminal failure not retained: %v / %v", first, second)
	}
	decoder = NewFrameDecoder(bytes.NewReader(append(append([]byte{}, valid...), valid...)))
	for i := 0; i < 2; i++ {
		if _, err := decoder.Next(); err != nil {
			t.Fatal("stateless codec must accept repeated response IDs", err)
		}
	}
}
