package libbox

import (
	"testing"

	"github.com/sagernet/sing-box/common/scopedhttp"
	"github.com/sagernet/sing/common/json"
)

func TestPublicIPPlanUsesActualEncodedConfigSnapshot(t *testing.T){
	ctx:=baseContext(nil)
	config:=`{"outbounds":[{"type":"selector","tag":"select","outbounds":["proxy"]},{"type":"socks","tag":"proxy","server":"192.0.2.1","server_port":1080}],"dns":{"final":"remote","servers":[{"type":"tcp","tag":"remote","server":"192.0.2.53","detour":"select"}]}}`
	options,err:=parseConfig(ctx,config);if err!=nil{t.Fatal(err)}
	snapshot,err:=json.MarshalContext(ctx,options);if err!=nil{t.Fatal(err)}
	plan,err:=scopedhttp.NewPlan(snapshot,[]string{"select","proxy"});if err!=nil{t.Fatalf("encoded snapshot=%s: %v",snapshot,err)}
	if plan.ID()==""{t.Fatal("missing immutable plan identity")}
}
