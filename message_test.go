package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestMessage_Marshal(t *testing.T) {

	msg := []byte("Hello brown fox")

	key := make([]byte, 2*aes.BlockSize)
	rand.Read(key)

	var b []byte
	{
		m, err := Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}

		b, err = m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("message mis-match")
	}
}
