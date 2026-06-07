package state

import (
	"encoding/binary"
	"errors"
)

// Wire format for a Proof. A proof must travel from a full node to a light
// client, so it needs a stable, self-describing byte encoding independent of
// Go's in-memory layout. The layout is:
//
//	Key      : KeySize bytes (fixed)
//	Bitmap   : KeySize bytes (fixed)
//	flags    : 1 byte  — bit0 = value present (inclusion)
//	value    : uvarint length + bytes   (only if inclusion)
//	siblings : uvarint count + count × (KeySize bytes)
//
// Every sibling is exactly KeySize bytes, so they are not length-prefixed
// individually. The count must equal the number of set bits in Bitmap, which
// VerifyProof already enforces structurally; UnmarshalBinary only checks that
// the buffer is well-formed.
var (
	ErrProofTruncated = errors.New("state: proof bytes truncated")
	ErrProofTrailing  = errors.New("state: proof bytes have trailing data")
)

const flagInclusion = 0x01

// MarshalBinary encodes the proof into its wire format.
func (p *Proof) MarshalBinary() ([]byte, error) {
	if p == nil || len(p.Key) != KeySize || len(p.Bitmap) != KeySize {
		return nil, ErrInvalidProof
	}

	out := make([]byte, 0, 2*KeySize+1+len(p.Value)+len(p.Siblings)*KeySize+8)
	out = append(out, p.Key...)
	out = append(out, p.Bitmap...)

	if p.Value != nil {
		out = append(out, flagInclusion)
		out = binary.AppendUvarint(out, uint64(len(p.Value)))
		out = append(out, p.Value...)
	} else {
		out = append(out, 0)
	}

	out = binary.AppendUvarint(out, uint64(len(p.Siblings)))
	for _, sib := range p.Siblings {
		if len(sib) != KeySize {
			return nil, ErrInvalidProof
		}
		out = append(out, sib...)
	}

	return out, nil
}

// UnmarshalBinary decodes a proof produced by MarshalBinary. It rejects
// truncated input and input with trailing bytes.
func (p *Proof) UnmarshalBinary(data []byte) error {
	r := reader{buf: data}

	key, ok := r.take(KeySize)
	if !ok {
		return ErrProofTruncated
	}
	bitmap, ok := r.take(KeySize)
	if !ok {
		return ErrProofTruncated
	}
	flags, ok := r.byteAt()
	if !ok {
		return ErrProofTruncated
	}

	var value []byte
	if flags&flagInclusion != 0 {
		n, ok := r.uvarint()
		if !ok {
			return ErrProofTruncated
		}
		b, ok := r.take(int(n))
		if !ok {
			return ErrProofTruncated
		}
		value = append([]byte(nil), b...)
	}

	count, ok := r.uvarint()
	if !ok {
		return ErrProofTruncated
	}
	siblings := make([][]byte, 0, count)
	for range count {
		b, ok := r.take(KeySize)
		if !ok {
			return ErrProofTruncated
		}
		siblings = append(siblings, append([]byte(nil), b...))
	}

	if !r.done() {
		return ErrProofTrailing
	}

	p.Key = append([]byte(nil), key...)
	p.Bitmap = append([]byte(nil), bitmap...)
	p.Value = value
	p.Siblings = siblings
	return nil
}

// reader is a minimal cursor over a byte slice for decoding.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, false
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, true
}

func (r *reader) byteAt() (byte, bool) {
	if r.pos >= len(r.buf) {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) uvarint() (uint64, bool) {
	v, n := binary.Uvarint(r.buf[r.pos:])
	if n <= 0 {
		return 0, false
	}
	r.pos += n
	return v, true
}

func (r *reader) done() bool { return r.pos == len(r.buf) }
