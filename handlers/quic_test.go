package handlers

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type failingWriter struct{}

func (f failingWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type concurrentDetectWriter struct {
	active        atomic.Int32
	maxActive     atomic.Int32
	concurrencyCh chan struct{}
}

func (w *concurrentDetectWriter) Write(p []byte) (int, error) {
	active := w.active.Add(1)
	for {
		currentMax := w.maxActive.Load()
		if active <= currentMax || w.maxActive.CompareAndSwap(currentMax, active) {
			break
		}
	}
	if active > 1 && w.concurrencyCh != nil {
		select {
		case w.concurrencyCh <- struct{}{}:
		default:
		}
	}
	time.Sleep(10 * time.Millisecond)
	w.active.Add(-1)
	return len(p), nil
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

func TestSessionStreamSerializesDirectAndHubWrites(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	writer := &concurrentDetectWriter{concurrencyCh: make(chan struct{}, 1)}
	stream := &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  writer,
	}
	hub.registerSession(remoteAddr, 123, stream)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := stream.writeFramed([]byte("response-payload")); err != nil {
			t.Errorf("direct write failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := hub.writeToIP(123, []byte("push-payload")); err != nil {
			t.Errorf("hub write failed: %v", err)
		}
	}()
	wg.Wait()

	select {
	case <-writer.concurrencyCh:
		t.Fatal("detected concurrent writes to the same session writer")
	default:
	}
	if writer.maxActive.Load() != 1 {
		t.Fatalf("expected maxActive=1, got %d", writer.maxActive.Load())
	}
}

func TestSessionStreamWriteUsesFramedSerialization(t *testing.T) {
	writer := &concurrentDetectWriter{}
	stream := &sessionStream{rawWriter: writer}

	n, err := stream.Write([]byte("payload"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("expected payload byte count, got %d", n)
	}
	if writer.maxActive.Load() != 1 {
		t.Fatalf("expected framed write to stay serialized, got %d", writer.maxActive.Load())
	}
}
