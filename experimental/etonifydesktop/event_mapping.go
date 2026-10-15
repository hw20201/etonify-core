package etonifydesktop

import (
	"encoding/json"
	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/protobuf/proto"
)

// MapDaemonEvent uses encoding/json deliberately: protojson encodes int64 as
// strings, but the existing Dart consumers require integer JSON tokens.
func MapDaemonEvent(kind string, data proto.Message, generation Snapshot) (Event, error) {
	var payload any
	method := kind
	switch kind {
	case "groups":
		groups, ok := data.(*daemon.Groups)
		if !ok || groups == nil {
			return Event{}, runtimeFailure("invalid_event", "Expected groups")
		}
		mapped := make([]any, 0, len(groups.Group))
		for _, g := range groups.Group {
			if g == nil {
				continue
			}
			items := make([]any, 0, len(g.Items))
			for _, it := range g.Items {
				if it != nil {
					items = append(items, map[string]any{"tag": it.Tag, "type": it.Type, "time": it.UrlTestTime, "delay": it.UrlTestDelay, "status": it.UrlTestStatus, "error": it.UrlTestError, "errorCode": it.UrlTestErrorCode})
				}
			}
			mapped = append(mapped, map[string]any{"tag": g.Tag, "type": g.Type, "selectable": g.Selectable, "selected": g.Selected, "isExpand": g.IsExpand, "items": items})
		}
		payload = map[string]any{"groups": mapped}
	case "traffic":
		v, ok := data.(*daemon.Status)
		if !ok || v == nil {
			return Event{}, runtimeFailure("invalid_event", "Expected traffic status")
		}
		payload = v
	case "logs":
		v, ok := data.(*daemon.Log)
		if !ok || v == nil {
			return Event{}, runtimeFailure("invalid_event", "Expected logs")
		}
		payload = map[string]any{"logs": v.Messages, "reset": v.Reset_}
	case "urltest", "urlTest":
		v, ok := data.(*daemon.URLTestUpdate)
		if !ok || v == nil {
			return Event{}, runtimeFailure("invalid_event", "Expected URLTest update")
		}
		method = "urlTest"
		p := map[string]any{}
		if v.Result != nil {
			p["result"] = v.Result
		}
		if v.Session != nil {
			b, err := json.Marshal(v.Session)
			if err != nil {
				return Event{}, err
			}
			var session map[string]json.RawMessage
			if err = json.Unmarshal(b, &session); err != nil {
				return Event{}, err
			}
			session["groupTag"], _ = json.Marshal(v.Session.OutboundTag)
			session["targetTag"], _ = json.Marshal(v.Session.TargetOutboundTag)
			delete(session, "outboundTag")
			delete(session, "targetOutboundTag")
			p["session"] = session
		}
		payload = p
	default:
		return Event{}, runtimeFailure("unsupported_event", "Unsupported daemon event")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, err
	}
	return Event{Version: ProtocolVersion, Kind: "event", SessionID: generation.SessionID, ConfigGeneration: generation.ConfigGeneration, NetworkGeneration: generation.NetworkGeneration, Method: method, Payload: raw}, nil
}
