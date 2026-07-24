//go:build !windows

package notify

// noopNotifier is the fallback for non-Windows platforms.
// cloakline still redacts silently; the user can check the /admin
// dashboard to see what was caught.
type noopNotifier struct{}

// New returns the no-op notifier for this platform.
func New() Notifier { return noopNotifier{} }

func (noopNotifier) Notify(_, _ string) {}
func (noopNotifier) Close()             {}
