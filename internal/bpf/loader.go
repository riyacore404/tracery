package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
)

type Tracer struct {
	collection *ebpf.Collection
	tracepoint link.Link
	CountsMap  *ebpf.Map
}

func NewTracer(bpfObjPath string, targetPID uint32) (*Tracer, error) {
	log.Debug().
		Str("bpf_obj", bpfObjPath).
		Uint32("target_pid", targetPID).
		Msg("initializing tracer")

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF object %q: %w", bpfObjPath, err)
	}

	log.Debug().Msg("BPF object loaded — setting constants")

	if targetPID != 0 {
		if err := spec.RewriteConstants(map[string]interface{}{
			"target_pid": targetPID,
		}); err != nil {
			return nil, fmt.Errorf("setting target_pid constant: %w", err)
		}
	}

	// This is where the BPF verifier runs — most errors surface here
	log.Debug().Msg("submitting BPF programs to kernel verifier")
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("kernel rejected BPF program: %w", err)
	}

	log.Debug().Msg("attaching tracepoint raw_syscalls/sys_enter")
	tp, err := link.Tracepoint(
		"raw_syscalls", "sys_enter",
		coll.Programs["count_syscalls"], nil,
	)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attaching sys_enter tracepoint: %w", err)
	}

	log.Info().
		Uint32("pid", targetPID).
		Msg("tracer attached successfully")

	return &Tracer{
		collection: coll,
		tracepoint: tp,
		CountsMap:  coll.Maps["syscall_counts"],
	}, nil
}

func (t *Tracer) Close() {
	log.Debug().Msg("detaching BPF program from kernel")
	if t.tracepoint != nil {
		t.tracepoint.Close()
	}
	if t.collection != nil {
		t.collection.Close()
	}
	log.Info().Msg("tracer detached cleanly")
}