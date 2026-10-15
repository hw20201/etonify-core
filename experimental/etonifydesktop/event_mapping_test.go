package etonifydesktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/route/rule"
)

func TestMapDaemonChunkAssemblyLimitRejectsWithoutTruncation(t *testing.T) {
	value, _ := json.Marshal(map[string]string{"data": strings.Repeat("x", MaximumAssemblyLength)})
	_, _, err := chunkEvent(Event{Version: 1, Kind: "event", Method: "groups", Payload: value})
	var typed *hostError
	if !errors.As(err, &typed) || typed.code != "resource_limit" {
		t.Fatalf("expected explicit resource limit, got %v", err)
	}
}

func TestMapDaemonTopologyAndSessionMatchDartConsumers(t *testing.T) {
	e, err := MapDaemonEvent("groups", &daemon.Groups{Group: []*daemon.Group{{Tag: "select", Items: []*daemon.GroupItem{{Tag: "a", UrlTestDelay: 123, UrlTestTime: 456, UrlTestStatus: "available"}}}}}, Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	json.Unmarshal(e.Payload, &p)
	item := p["groups"].([]any)[0].(map[string]any)["items"].([]any)[0].(map[string]any)
	if item["delay"] != float64(123) || item["time"] != float64(456) || item["status"] != "available" {
		t.Fatalf("legacy topology lost: %s", e.Payload)
	}
	e, err = MapDaemonEvent("urlTest", &daemon.URLTestUpdate{Session: &daemon.URLTestSessionStatus{OutboundTag: "select", TargetOutboundTag: "a", SessionId: 9}}, Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(e.Payload, &p)
	session := p["session"].(map[string]any)
	if e.Method != "urlTest" || session["groupTag"] != "select" || session["targetTag"] != "a" || session["sessionId"] != float64(9) {
		t.Fatalf("session mapping: %s", e.Payload)
	}
	if _, err = MapDaemonEvent("groups", &daemon.Log{}, Snapshot{}); err == nil {
		t.Fatal("wrong proto type accepted")
	}
}

func TestHostProcessPathPolicyAcceptedByActualCore(t *testing.T) {
	// Literal emitted by Dart RegExp.escape for C:\Apps\a+b(1)\client.exe.
	pattern := `(?i)^C:\\Apps\\a\+b\(1\)\\client\.exe$`
	h := newTestHost(t)
	var config map[string]any
	json.Unmarshal([]byte(localConfig(freePort(t))), &config)
	config["route"] = map[string]any{"rules": []any{map[string]any{"process_path_regex": []string{pattern}, "outbound": "direct"}}}
	raw, _ := json.Marshal(config)
	if err := h.daemon.CheckConfig(context.Background(), string(raw)); err != nil {
		t.Fatal(err)
	}
	matcher, err := rule.NewProcessPathRegexItem([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path string
		want bool
	}{
		{`C:\Apps\a+b(1)\client.exe`, true}, {`c:\APPS\A+B(1)\CLIENT.EXE`, true}, {`C:\Other\client.exe`, false}, {`C:\Apps\ab1\client.exe`, false}, {`C:\Apps\a+b(1)\client.exe.bak`, false},
	} {
		if got := matcher.Match(&adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{ProcessPaths: []string{tt.path}}}); got != tt.want {
			t.Errorf("path %q matched=%v", tt.path, got)
		}
	}
}

func TestMapDaemon4505RecordsChunkRoundTrip(t *testing.T) {
	g := &daemon.Groups{Group: []*daemon.Group{{Tag: "select"}}}
	for i := 0; i < 4505; i++ {
		g.Group[0].Items = append(g.Group[0].Items, &daemon.GroupItem{Tag: string(bytes.Repeat([]byte{'x'}, 80)), UrlTestDelay: 123})
	}
	e, err := MapDaemonEvent("groups", g, Snapshot{SessionID: "captured", ConfigGeneration: 4, NetworkGeneration: 7})
	if err != nil {
		t.Fatal(err)
	}
	chunks, descriptor, err := chunkEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor == nil || len(chunks) < 2 {
		t.Fatal("topology not chunked")
	}
	var assembled []byte
	for i, c := range chunks {
		frame, err := EncodeFrame(c)
		if err != nil || len(frame) > 64*1024 {
			t.Fatalf("oversized chunk %d: %d %v", i, len(frame), err)
		}
		if c.SessionID != "captured" || c.ConfigGeneration != 4 || c.NetworkGeneration != 7 || c.Method != "streamChunk" {
			t.Fatal("chunk generation changed")
		}
		var p struct {
			Index      int    `json:"index"`
			Total      int    `json:"total"`
			TotalBytes int    `json:"totalBytes"`
			Data       string `json:"data"`
		}
		json.Unmarshal(c.Payload, &p)
		if p.Index != i || p.Total != len(chunks) || p.TotalBytes != len(e.Payload) {
			t.Fatal("chunk bounds changed")
		}
		part, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil {
			t.Fatal(err)
		}
		assembled = append(assembled, part...)
	}
	if !bytes.Equal(assembled, e.Payload) {
		t.Fatal("chunk assembly corrupted topology")
	}
}

func TestMapDaemonEventPreservesGeneration(t *testing.T) {
	s := Snapshot{SessionID: "old", ConfigGeneration: 4, NetworkGeneration: 6}
	e, err := MapDaemonEvent("urltest", &daemon.URLTestUpdate{Result: &daemon.URLTestResult{Tag: "proxy", NetworkGeneration: 3, Revision: 11}}, s)
	if err != nil {
		t.Fatal(err)
	}
	if e.SessionID != "old" || e.ConfigGeneration != 4 || e.NetworkGeneration != 6 {
		t.Fatalf("relabelled captured generation: %+v", e)
	}
	var p map[string]any
	json.Unmarshal(e.Payload, &p)
	if p["result"].(map[string]any)["revision"] != float64(11) {
		t.Fatalf("revision lost/nonnumeric: %s", e.Payload)
	}
	if _, err := MapDaemonEvent("shell", &daemon.URLTestUpdate{}, s); err == nil {
		t.Fatal("unknown event accepted")
	}
}
