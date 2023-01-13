package update

import "github.com/pkg/errors"

// TODO: the platform resolution should also be
// in the interface...

// Errors.
var (
	// ErrNotFound is returned from GetRelease if the release is not found.
	ErrNotFound = errors.New("release not found")
)

// Store is the interface used for listing and fetching releases.
type Store interface {
	GetRelease(version string) (*Release, error)
	LatestReleases() ([]*Release, error)
}
