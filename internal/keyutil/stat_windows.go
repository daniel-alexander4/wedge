//go:build windows

package keyutil

func fileUID(stat interface{}) int {
	return -1
}
