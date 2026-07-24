package api

// Caps is a typed capability set for an Upstream. Booleans do not survive the
// second provider — see docs/interface-contracts.md.
type Caps struct {
	Modalities ModalitySet
	Tools      ToolCaps
	Streaming  StreamCaps
	MaxContext int // tokens
	JSONMode   JSONModeCaps
	Reasoning  ReasoningCaps
}

// ModalitySet is a bitset over Modality values.
type ModalitySet uint32

func (s ModalitySet) Has(m Modality) bool { return s&(1<<uint(m)) != 0 }
func (s ModalitySet) With(m Modality) ModalitySet {
	return s | (1 << uint(m))
}

// Covers reports whether s contains all of other's set bits.
func (s ModalitySet) Covers(other ModalitySet) bool { return s&other == other }

// Modalities returns the list of set modalities in stable order.
func (s ModalitySet) Modalities() []Modality {
	var out []Modality
	for m := Modality(1); m <= ModOffice; m++ {
		if s.Has(m) {
			out = append(out, m)
		}
	}
	return out
}

// ToolCaps flags what tool-invocation semantics the upstream supports.
type ToolCaps uint16

const (
	ToolNone            ToolCaps = 0
	ToolFunctionCalling ToolCaps = 1 << iota
	ToolStrictSchema
	ToolParallelCalls
)

func (c ToolCaps) Has(f ToolCaps) bool { return c&f == f }

// StreamCaps flags what streaming shape the upstream produces.
type StreamCaps uint8

const (
	StreamNone StreamCaps = iota
	StreamSSE
	StreamWSFrames
)

// JSONModeCaps flags structured-output support.
type JSONModeCaps uint8

const (
	JSONNone JSONModeCaps = iota
	JSONFreeform
	JSONStrictSchema
)

// ReasoningCaps flags exposed-reasoning support.
type ReasoningCaps uint8

const (
	ReasoningNone ReasoningCaps = iota
	ReasoningHidden
	ReasoningExposed
)
