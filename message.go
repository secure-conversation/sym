package sym

import (
	"encoding/base64"
	"encoding/json"
)

// Message holds the details of an encrypted message
type Message struct {
	Algo       Algo
	Ciphertext []byte
	Nonce      []byte
}

// Marshal converts the Message to JSON
func (m *Message) Marshal() ([]byte, error) {

	jm := &jsonMessage{
		Algo:       m.Algo.String(),
		Ciphertext: base64.RawStdEncoding.EncodeToString(m.Ciphertext),
		Nonce:      base64.RawStdEncoding.EncodeToString(m.Nonce),
	}

	return json.Marshal(jm)
}

// ParseMessage decodes the JSON to a Message
func ParseMessage(data []byte) (*Message, error) {
	var jm jsonMessage

	err := json.Unmarshal(data, &jm)
	if err != nil {
		return nil, err
	}

	c, err := base64.RawStdEncoding.DecodeString(jm.Ciphertext)
	if err != nil {
		return nil, err
	}
	n, err := base64.RawStdEncoding.DecodeString(jm.Nonce)
	if err != nil {
		return nil, err
	}
	a, err := ParseAlgo(jm.Algo)
	if err != nil {
		return nil, err
	}

	return &Message{
		Algo:       a,
		Ciphertext: c,
		Nonce:      n,
	}, nil
}

type jsonMessage struct {
	Algo       string `json:"a"`
	Ciphertext string `json:"c"`
	Nonce      string `json:"n"`
}
