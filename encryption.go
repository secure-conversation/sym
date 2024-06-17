package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Message holds the details of an encrypted message
type Message struct {
	Algo       Algo
	Ciphertext []byte
	Nonce      []byte
}

var ErrInvalidAESKey = errors.New("invalid key")

// Encrypt implements AES GCM encryption
func Encrypt(msg, key []byte) (*Message, error) {
	return EncryptUsingAlgo(msg, key, AESGCM)
}

// EncryptUsingAlgo implements encryption with the choice of algo
func EncryptUsingAlgo(msg, key []byte, algo Algo) (*Message, error) {

	aesgcm := func() (*Message, error) {
		if len(key) != aes.BlockSize && len(key) != 2*aes.BlockSize {
			return nil, ErrInvalidAESKey
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		return &Message{
			Algo:       AESGCM,
			Ciphertext: aesgcm.Seal(nil, nonce, msg, nil),
			Nonce:      nonce,
		}, nil
	}

	switch algo {
	case AESGCM:
		return aesgcm()
	default:
		return nil, ErrUnknownAlgo
	}
}

// ErrMessageMissing returned when Decrypt receives a nil Message
var ErrMessageMissing = errors.New("msg must be provided")

// ErrMessageInvalid returned when Decrypt receives a Message with invalid details
var ErrMessageInvalid = errors.New("invalid Message details")

// Decrypt implements AES GCM decryption
func Decrypt(msg *Message, key []byte) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ErrMessageInvalid
		}
	}()

	if msg == nil {
		return nil, ErrMessageMissing
	}
	if len(msg.Nonce) == 0 || len(msg.Ciphertext) == 0 {
		return nil, ErrMessageInvalid
	}
	if len(key) != aes.BlockSize && len(key) != 2*aes.BlockSize {
		return nil, ErrInvalidAESKey
	}

	switch msg.Algo {
	case AESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return aesgcm.Open(nil, msg.Nonce, msg.Ciphertext, nil)
	default:
		return nil, ErrUnknownAlgo
	}
}
