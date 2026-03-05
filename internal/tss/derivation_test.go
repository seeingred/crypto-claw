package tss

import (
	"math/big"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		path    string
		want    []uint32
		wantErr bool
	}{
		{
			path: "m/44'/60'/0'/0/0",
			want: []uint32{44 + hardenedOffset, 60 + hardenedOffset, 0 + hardenedOffset, 0, 0},
		},
		{
			path: "m/44'/501'/0'/0'",
			want: []uint32{44 + hardenedOffset, 501 + hardenedOffset, 0 + hardenedOffset, 0 + hardenedOffset},
		},
		{
			path: "44h/60h/0h/0/0",
			want: []uint32{44 + hardenedOffset, 60 + hardenedOffset, 0 + hardenedOffset, 0, 0},
		},
		{
			path:    "",
			wantErr: true,
		},
		{
			path:    "m/abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := parsePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parsePath(%q) got %d components, want %d", tt.path, len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("parsePath(%q)[%d] = %d, want %d", tt.path, i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestCompressPublicKey(t *testing.T) {
	x := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	yEven := new(big.Int).SetInt64(2) // even
	yOdd := new(big.Int).SetInt64(3)  // odd

	compEven := compressPublicKey(x, yEven, nil)
	if len(compEven) != 33 {
		t.Errorf("expected 33 bytes, got %d", len(compEven))
	}
	if compEven[0] != 0x02 {
		t.Errorf("expected prefix 0x02 for even y, got 0x%02x", compEven[0])
	}

	compOdd := compressPublicKey(x, yOdd, nil)
	if compOdd[0] != 0x03 {
		t.Errorf("expected prefix 0x03 for odd y, got 0x%02x", compOdd[0])
	}
}
