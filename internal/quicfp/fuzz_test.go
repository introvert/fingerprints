package quicfp

import "testing"

func FuzzObserve(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x41, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		NewTable().Observe("1.2.3.4:5", b)
	})
}

func FuzzAppStreams(f *testing.F) {
	f.Add([]byte{0x0a, 0x02, 0x05, 0x00, 0x04, 0x02, 0x01, 0x00}, []byte{0x00, 0x00, 0xd1, 0xd7})
	f.Fuzz(func(t *testing.T, frames, field []byte) {
		a := newAppState(make([]byte, 32))
		a.frames(frames)
		a.addStream(0, 0, append([]byte{0x01, byte(len(field) & 0x3f)}, field...))
		a.addStream(2, 0, append([]byte{0x00, 0x04, byte(len(field) & 0x3f)}, field...))
		a.control()
		a.request(0)
		scanQPACK(field)
		decodePN(int64(len(field)), uint64(len(frames)), 1+len(field)%4)
	})
}
