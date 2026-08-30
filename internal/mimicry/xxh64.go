package mimicry

import "encoding/binary"

// xxHash64 primes (cyan4973). Present in claude.exe 2.1.251 as little-endian
// immediates; 2.1.177 cch used this hash with seed CCHSeed177.
const (
	xxhP1 uint64 = 0x9E3779B185EBCA87
	xxhP2 uint64 = 0xC2B2AE3D27D4EB4F
	xxhP3 uint64 = 0x165667B19E3779F9
	xxhP4 uint64 = 0x85EBCA77C2B2AE63
	xxhP5 uint64 = 0x27D4EB2F165667C5
)

func rotl64(x uint64, r uint) uint64 {
	return (x << r) | (x >> (64 - r))
}

func xxhRound(acc, input uint64) uint64 {
	acc += input * xxhP2
	acc = rotl64(acc, 31)
	acc *= xxhP1
	return acc
}

func xxhMerge(acc, val uint64) uint64 {
	acc ^= xxhRound(0, val)
	acc = acc*xxhP1 + xxhP4
	return acc
}

func xxh64(input []byte, seed uint64) uint64 {
	n := len(input)
	var h uint64
	i := 0
	if n >= 32 {
		v1 := seed + xxhP1 + xxhP2
		v2 := seed + xxhP2
		v3 := seed
		v4 := seed - xxhP1
		for i+32 <= n {
			v1 = xxhRound(v1, binary.LittleEndian.Uint64(input[i:]))
			v2 = xxhRound(v2, binary.LittleEndian.Uint64(input[i+8:]))
			v3 = xxhRound(v3, binary.LittleEndian.Uint64(input[i+16:]))
			v4 = xxhRound(v4, binary.LittleEndian.Uint64(input[i+24:]))
			i += 32
		}
		h = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)
		h = xxhMerge(h, v1)
		h = xxhMerge(h, v2)
		h = xxhMerge(h, v3)
		h = xxhMerge(h, v4)
	} else {
		h = seed + xxhP5
	}
	h += uint64(n)
	for i+8 <= n {
		k := binary.LittleEndian.Uint64(input[i:])
		h ^= xxhRound(0, k)
		h = rotl64(h, 27)*xxhP1 + xxhP4
		i += 8
	}
	if i+4 <= n {
		h ^= uint64(binary.LittleEndian.Uint32(input[i:])) * xxhP1
		h = rotl64(h, 23)*xxhP2 + xxhP3
		i += 4
	}
	for i < n {
		h ^= uint64(input[i]) * xxhP5
		h = rotl64(h, 11) * xxhP1
		i++
	}
	h ^= h >> 33
	h *= xxhP2
	h ^= h >> 29
	h *= xxhP3
	h ^= h >> 32
	return h
}
