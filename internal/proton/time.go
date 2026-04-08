package proton

import "time"

// nowUnix is split out so tests can replace it via a Pool nowFn.
func nowUnix() int64 { return time.Now().Unix() }
