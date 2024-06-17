sym
===

[![Go Doc](https://pkg.go.dev/badge/github.com/secure-conversation/sym.svg)](https://pkg.go.dev/github.com/secure-conversation/sym)
[![Go Report Card](https://goreportcard.com/badge/github.com/secure-conversation/sym)](https://goreportcard.com/report/github.com/secure-conversation/sym)


This project implements symmetric encryption.

Currently the only supported encryption is AES-GCM

Example:

```go
package main

import (
  "crypto/aes"
  "crypto/rand"
  "github.com/secure-conversation/sym"
)

func main() {
  
  msg := []byte("Hello World")

  key := make([]byte, 2*aes.BlockSize)
  rand.Read(key)

  m, _ := sym.Encrypt(msg, key)

  b, _ := m.Marshal()

  fmt.Println(string(b))
}
```

Note the JSON representation of the `Message` struct uses base64 raw std encoding.

