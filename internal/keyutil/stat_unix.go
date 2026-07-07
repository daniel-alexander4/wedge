//go:build !windows

package keyutil

import "syscall"

func fileUID(stat interface{}) int {
	if s, ok := stat.(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
