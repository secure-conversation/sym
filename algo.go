package sym

import "errors"

// Algo signifies a specific algorithm for symmetric encryption.
// Currently only aes-gcm is supported
type Algo int

func (a Algo) String() string {
	switch a {
	case AESGCM:
		return aesgcmStr
	default:
		return ""
	}
}

// ErrUnknownAlgo returned when a supported Algo is not identified
var ErrUnknownAlgo = errors.New("unknown algo")

// ParseAlgo returns the Algo from the string
func ParseAlgo(s string) (Algo, error) {
	switch s {
	case aesgcmStr:
		return AESGCM, nil
	default:
		return -1, ErrUnknownAlgo
	}
}

const (
	AESGCM Algo = iota
)

const (
	aesgcmStr string = "aes-gcm"
)
