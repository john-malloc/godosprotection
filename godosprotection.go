package godosprotection

import "time"

type dosReq struct {
	host   string
	path   string
	method string
}

var dos = make(map[dosReq]time.Time)

// Check for DoS, attack return true if host is makeing too many requests or false if it isn't
func IsDos(host []byte, path []byte, method []byte) bool {
	thisDosReq := dosReq{
		host:   string(host),
		path:   string(path),
		method: string(method),
	}
	// The last connection from this host
	lastCon := dos[thisDosReq]
	// If the last connection was to little time ago return true
	if time.Since(lastCon) < time.Second {
		return true
	}
	dos[thisDosReq] = time.Now()
	return false
}
