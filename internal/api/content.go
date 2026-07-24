package api

import "time"

// Modality tags a Content atom. See docs/architecture.md — modality-first.
type Modality uint8

const (
	ModUnknown Modality = 0
	ModText    Modality = 1
	ModImage   Modality = 2
	ModAudio   Modality = 3
	ModVideo   Modality = 4
	ModPDF     Modality = 5
	ModArchive Modality = 6
	ModOffice  Modality = 7
)

// String is stable and matches CEL environment expectations.
func (m Modality) String() string {
	switch m {
	case ModText:
		return "text"
	case ModImage:
		return "image"
	case ModAudio:
		return "audio"
	case ModVideo:
		return "video"
	case ModPDF:
		return "pdf"
	case ModArchive:
		return "archive"
	case ModOffice:
		return "office"
	default:
		return "unknown"
	}
}

// ContentOrigin is the provenance of a Content atom. Critical for guardrails —
// retrieved and tool-output content receive stricter treatment than user input.
type ContentOrigin uint8

const (
	OriginUnknown     ContentOrigin = 0
	OriginUserInput   ContentOrigin = 1
	OriginRetrievedRAG ContentOrigin = 2
	OriginToolOutput  ContentOrigin = 3
	OriginModelOutput ContentOrigin = 4
	OriginSystem      ContentOrigin = 5
)

// Dim is image/video dimensions.
type Dim struct {
	W, H int
}

// ContentMeta is typed metadata for a Content atom.
type ContentMeta struct {
	MIME       string
	Filename   string
	Dimensions *Dim
	Duration   time.Duration
	Language   string
	Origin     ContentOrigin
}

// Content is a modality-tagged payload atom.
// Bytes is the raw payload; interpretation depends on Modality.
// For ModText, Bytes is UTF-8. For binary modalities, Bytes is the raw bytes.
type Content struct {
	Modality Modality
	Bytes    []byte
	Meta     ContentMeta
}

// TextString returns the text content, or "" if not a text modality.
// Never allocates a new backing array.
func (c Content) TextString() string {
	if c.Modality != ModText {
		return ""
	}
	return string(c.Bytes)
}
