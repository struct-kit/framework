package postgres

import (
	"crypto/md5"
	"encoding/hex"
)

// hashMD5Password implements Postgres's md5 auth method exactly as
// documented: concat("md5", md5hex(concat(md5hex(concat(password,
// username)), salt))) — password first in the inner hash, and the salt is
// concatenated as raw bytes (not hex text) to the ASCII hex string from
// the inner hash.
func hashMD5Password(user, password string, salt [4]byte) string {
	inner := md5Hex(password + user)
	outer := md5Hex(inner + string(salt[:]))
	return "md5" + outer
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
