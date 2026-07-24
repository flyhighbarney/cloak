// Package notify fires user-visible alerts when cloakline silently
// redacts HIGH-tier findings. The platform-specific implementations
// live in sibling files distinguished by build tags.
//
// Usage:
//
//	n := notify.New()
//	defer n.Close()
//	n.Notify("password", "http://127.0.0.1:4001/admin/session/allow?nonce=abc123")
//
// The allowURL, when opened in a browser, grants the current session
// one-hour permission to bypass HIGH-tier redaction so the user can
// resend their original message unmodified.
package notify

// Notifier fires visual alerts when cloakline silently redacts a
// HIGH-tier finding. New() returns the platform-appropriate
// implementation; on unsupported platforms it returns a no-op.
type Notifier interface {
	// Notify fires an alert for a detected finding of `kind` (e.g.
	// "password", "api_key"). `allowURL` is a one-time URL the user
	// can open in a browser to permit future HIGH-tier pastes for this
	// session. Notify must return quickly — heavy work should run in a
	// goroutine inside the implementation.
	Notify(kind, allowURL string)

	// Close releases any OS resources held by the notifier (tray
	// icons, temp files, etc.). Safe to call more than once.
	Close()
}
