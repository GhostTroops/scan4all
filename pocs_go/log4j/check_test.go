package log4j

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"testing"
)

func TestSolr(t *testing.T) {
	util.Init2()
	type args struct {
		u string
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "test Solr", args: args{"http://127.0.0.1:8983/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Solr(tt.args.u)
		})
	}
}
