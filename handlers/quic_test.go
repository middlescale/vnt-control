package handlers

import (
	"errors"
	"io"
	"net"
	"testing"
)

type failingWriter struct{}

func (f failingWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestStreamHubWriteToIPReturnsUnavailableWithoutRegisteredStream(t *testing.T) {
	hub := newStreamHub()

	err := hub.writeToIP(123, []byte("payload"))
	if !errors.Is(err, errStreamUnavailable) {
		t.Fatalf("expected errStreamUnavailable, got %v", err)
	}
}

func TestStreamHubWriteToIPRemovesStaleStreamOnWriteFailure(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	hub.register(remoteAddr, 123, failingWriter{})

	err := hub.writeToIP(123, []byte("payload"))
	if err == nil {
		t.Fatalf("expected write failure")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected wrapped io.ErrClosedPipe, got %v", err)
	}

	err = hub.writeToIP(123, []byte("payload"))
	if !errors.Is(err, errStreamUnavailable) {
		t.Fatalf("expected stale stream removal after write failure, got %v", err)
	}
}
