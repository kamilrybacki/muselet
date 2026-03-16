package scanner

import (
	"encoding/binary"
	"hash"
	"hash/fnv"
	"math"
)

// BloomFilter is a probabilistic set membership structure.
type BloomFilter struct {
	bits []byte
	k    uint
	m    uint
}

// NewBloomFilter creates a new bloom filter sized for n elements at the given FP rate.
func NewBloomFilter(n uint, fpRate float64) *BloomFilter {
	m := optimalM(n, fpRate)
	k := optimalK(m, n)
	return &BloomFilter{
		bits: make([]byte, (m+7)/8),
		k:    k,
		m:    m,
	}
}

// BloomFilterFromBytes restores a bloom filter from serialized data.
// The data must have been produced by BloomFilter.Bytes(), which prefixes
// the raw bit array with an 8-byte little-endian uint64 encoding of m.
func BloomFilterFromBytes(data []byte, k uint) *BloomFilter {
	if len(data) < 8 {
		// Fallback for legacy data without the m prefix
		return &BloomFilter{
			bits: data,
			k:    k,
			m:    uint(len(data)) * 8,
		}
	}
	m := uint(binary.LittleEndian.Uint64(data[:8]))
	return &BloomFilter{
		bits: data[8:],
		k:    k,
		m:    m,
	}
}

// Add adds an element to the filter.
func (bf *BloomFilter) Add(data []byte) {
	for _, h := range bf.hashes(data) {
		pos := h % bf.m
		bf.bits[pos/8] |= 1 << (pos % 8)
	}
}

// Test checks if an element might be in the filter.
func (bf *BloomFilter) Test(data []byte) bool {
	for _, h := range bf.hashes(data) {
		pos := h % bf.m
		if bf.bits[pos/8]&(1<<(pos%8)) == 0 {
			return false
		}
	}
	return true
}

// Bytes returns the serialized filter bytes.
// The format is: 8 bytes little-endian uint64 of m, followed by the bit array.
func (bf *BloomFilter) Bytes() []byte {
	result := make([]byte, 8+len(bf.bits))
	binary.LittleEndian.PutUint64(result[:8], uint64(bf.m))
	copy(result[8:], bf.bits)
	return result
}

// K returns the number of hash functions.
func (bf *BloomFilter) K() uint {
	return bf.k
}

// Cap returns the capacity in bits.
func (bf *BloomFilter) Cap() uint {
	return bf.m
}

func (bf *BloomFilter) hashes(data []byte) []uint {
	hashes := make([]uint, bf.k)
	h1 := hashFNV64(data)
	h2 := hashFNV32(data)
	for i := uint(0); i < bf.k; i++ {
		hashes[i] = uint(h1 + uint64(i)*uint64(h2))
	}
	return hashes
}

func hashFNV64(data []byte) uint64 {
	var h hash.Hash64 = fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

func hashFNV32(data []byte) uint32 {
	var h hash.Hash32 = fnv.New32a()
	h.Write(data)
	return h.Sum32()
}

func optimalM(n uint, fpRate float64) uint {
	return uint(math.Ceil(-float64(n) * math.Log(fpRate) / (math.Log(2) * math.Log(2))))
}

func optimalK(m, n uint) uint {
	k := uint(math.Ceil(float64(m) / float64(n) * math.Log(2)))
	if k < 1 {
		k = 1
	}
	return k
}
