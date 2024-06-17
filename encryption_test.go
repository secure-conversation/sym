package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"testing"
)

func ExampleEncrypt() {
	msg := []byte("Hello World")

	key := make([]byte, 2*aes.BlockSize)
	rand.Read(key)

	m, _ := Encrypt(msg, key)

	msg1, _ := Decrypt(m, key)

	fmt.Println(bytes.Equal(msg, msg1))
	// Output: true
}

func TestEncrypt(t *testing.T) {
	msg := []byte("Hello World")

	key := make([]byte, 2*aes.BlockSize)
	rand.Read(key)

	m, err := Encrypt(msg, key)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("Messages are not the same")
	}
}

func TestEncrypt_1(t *testing.T) {
	msg := []byte("Hello World")

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	m, err := Encrypt(msg, key)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("Messages are not the same")
	}
}

func TestEncrypt_2(t *testing.T) {
	msg := []byte("Hello World")

	key := make([]byte, aes.BlockSize-1)
	rand.Read(key)

	_, err := Encrypt(msg, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrInvalidAESKey {
		t.Fatal(fmt.Printf("unexpected err: wanted %s, got %s", ErrInvalidAESKey, err))
	}
}

func TestEncrypt_3(t *testing.T) {

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		key := make([]byte, aes.BlockSize)
		rand.Read(key)

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	key := make([]byte, aes.BlockSize-1)
	rand.Read(key)

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrInvalidAESKey {
		t.Fatal(fmt.Printf("unexpected err: wanted %s, got %s\n", ErrInvalidAESKey, err))
	}
}

func TestEncrypt_4(t *testing.T) {
	msg := []byte("")

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	m, err := Encrypt(msg, key)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("Messages are not the same")
	}
}

func TestEncrypt_5(t *testing.T) {

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		key := make([]byte, aes.BlockSize)
		rand.Read(key)

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err = Decrypt(m, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrInvalidAESKey {
		t.Fatal(fmt.Printf("unexpected err: wanted %s, got %s\n", ErrInvalidAESKey, err))
	}
}

func TestEncrypt_6(t *testing.T) {

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		key := make([]byte, aes.BlockSize)
		rand.Read(key)

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Error() != "cipher: message authentication failed" {
		t.Fatal(fmt.Printf("unexpected err: wanted 'cipher: message authentication failed', got %s\n", err))
	}
}

func TestEncrypt_7(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - nonce changed and different length
	m.Nonce = []byte("12345")

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrMessageInvalid {
		t.Fatal(fmt.Printf("unexpected err: wanted '%s', got %s\n", ErrMessageInvalid, err))
	}
}

func TestEncrypt_8(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - nonce changed and same length
	n := make([]byte, len(m.Nonce))
	rand.Read(n)
	m.Nonce = n

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Error() != "cipher: message authentication failed" {
		t.Fatal(fmt.Printf("unexpected err: wanted 'cipher: message authentication failed', got %s\n", err))
	}
}

func TestEncrypt_9(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - nonce removed
	m.Nonce = nil

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrMessageInvalid {
		t.Fatal(fmt.Printf("unexpected err: wanted '%s', got %s\n", ErrMessageInvalid, err))
	}
}

func TestEncrypt_10(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - ciphertext removed
	m.Ciphertext = nil

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrMessageInvalid {
		t.Fatal(fmt.Printf("unexpected err: wanted '%s', got %s\n", ErrMessageInvalid, err))
	}
}

func TestEncrypt_11(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - ciphertext changed, different length
	m.Ciphertext = []byte("abcdef")

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Error() != "cipher: message authentication failed" {
		t.Fatal(fmt.Printf("unexpected err: wanted 'cipher: message authentication failed', got %s\n", err))
	}
}

func TestEncrypt_12(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - ciphertext changed, same length
	c := make([]byte, len(m.Ciphertext))
	rand.Read(c)
	m.Ciphertext = c

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Error() != "cipher: message authentication failed" {
		t.Fatal(fmt.Printf("unexpected err: wanted 'cipher: message authentication failed', got %s\n", err))
	}
}

func TestEncrypt_13(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	var m *Message
	var err error
	{
		msg := []byte("Hello World")

		m, err = Encrypt(msg, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tampered Message - change Algo
	m.Algo = -99

	_, err = Decrypt(m, key)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrUnknownAlgo {
		t.Fatal(fmt.Printf("unexpected err: wanted '%s', got %s\n", ErrUnknownAlgo, err))
	}
}

func TestEncryptUsingAlgo(t *testing.T) {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	msg := []byte("Hello World")

	_, err := EncryptUsingAlgo(msg, key, -1)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrUnknownAlgo {
		t.Fatal(fmt.Printf("unexpected err: wanted '%s', got %s\n", ErrUnknownAlgo, err))
	}
}

func TestEncryptUsingAlgo_1(t *testing.T) {

	msg := []byte("Hello World")

	key := make([]byte, 2*aes.BlockSize)
	rand.Read(key)

	m, err := EncryptUsingAlgo(msg, key, AESGCM)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("Messages are not the same")
	}
}

func TestEncryptUsingAlgo_2(t *testing.T) {

	msg := []byte("Hello World")

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	m, err := EncryptUsingAlgo(msg, key, AESGCM)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := Decrypt(m, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, msg1) {
		t.Fatal("Messages are not the same")
	}
}
