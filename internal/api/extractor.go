package api

import "context"

// Extractor decomposes one Content into zero or more Contents.
// A PDF extractor might return text + images; an archive extractor might
// return many contents; a text passthrough returns the same content.
type Extractor interface {
	APIVersion() string
	Handles(m Modality) bool
	Extract(ctx context.Context, in Content) ([]Content, error)
}
