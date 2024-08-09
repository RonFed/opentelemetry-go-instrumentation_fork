// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package poc


import (
	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "main"
)

// New returns a new [probe.Probe].
func New(logger logr.Logger) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindClient,
		InstrumentedPkg: pkg,
	}
	return &probe.Base[bpfObjects, event]{
		ID:     id,
		Logger: logger.WithName(id.String()),
		Consts: []probe.Const{
			probe.RegistersABIConst{},
			probe.AllocationConst{},
		},
		Uprobes: []probe.Uprobe{
			{
				Sym:         "main.probedFunction",
				EntryProbe:  "uprobe_probedFunction",
			},
		},

		SpecFn:    loadBpf,
		ProcessFn: convertEvent,
	}
}

// event represents an event in an SQL database
// request-response.
type event struct {
	context.BaseSpanProperties
}

func convertEvent(e *event) []*probe.SpanEvent {
	return []*probe.SpanEvent{}
}

