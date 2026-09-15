package mysql

import "crypto/sha1"

// scrambleNativePassword implements mysql_native_password exactly as
// documented: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password))).
// An empty password produces an empty auth response (no scrambling).
func scrambleNativePassword(password string, scramble []byte) []byte {
	if password == "" {
		return nil
	}
	sha1Password := sha1Sum([]byte(password))
	sha1Sha1Password := sha1Sum(sha1Password)

	combined := make([]byte, 0, len(scramble)+len(sha1Sha1Password))
	combined = append(combined, scramble...)
	combined = append(combined, sha1Sha1Password...)
	sha1ScrambleHash := sha1Sum(combined)

	result := make([]byte, len(sha1Password))
	for i := range result {
		result[i] = sha1Password[i] ^ sha1ScrambleHash[i]
	}
	return result
}

func sha1Sum(b []byte) []byte {
	sum := sha1.Sum(b)
	return sum[:]
}
