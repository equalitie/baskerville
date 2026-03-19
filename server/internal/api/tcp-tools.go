package api

import (
	"io"
	"log"
)

// ensures requests are always drained to be able to reuse TCP connection
func DrainBody(body io.ReadCloser) {
	_, err := io.Copy(io.Discard, body)
	if err != nil {
		log.Printf("ErrDiscardingBody: %s", err)
	}
	err = body.Close()
	if err != nil {
		log.Printf("ErrClosingBody: %s", err)
	}
}
