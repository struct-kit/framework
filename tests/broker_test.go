package tests

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/events"
)

func TestBroker_MemoryPublishAndSubscribe(t *testing.T) {
	cfg := config.Config{
		BrokerDriver: "memory",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	broker, err := events.NewBroker(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected broker init error: %v", err)
	}

	if broker.Driver != "memory" {
		t.Errorf("expected driver memory, got %s", broker.Driver)
	}

	received := make(chan events.Event, 1)
	inMemPub, ok := broker.Publisher.(*events.InMemoryPublisher)
	if !ok {
		t.Fatalf("expected *events.InMemoryPublisher")
	}

	inMemPub.Subscribe("UserCreatedV1", func(ctx context.Context, e events.Event) error {
		received <- e
		return nil
	})

	evt := events.Event{
		ID:          "evt-100",
		Name:        "UserCreatedV1",
		AggregateID: "user-42",
		OccurredAt:  time.Now().UTC(),
		Payload:     map[string]string{"email": "user@example.com"},
	}

	err = broker.Publisher.Publish(context.Background(), evt)
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	select {
	case got := <-received:
		if got.ID != "evt-100" || got.AggregateID != "user-42" {
			t.Errorf("received event mismatch: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event delivery")
	}
}

func TestBroker_DriverChoices(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, driver := range []string{"memory", "log", "redis", "nats", "kafka"} {
		cfg := config.Config{
			BrokerDriver: driver,
			BrokerURL:    "localhost:9092",
		}
		b, err := events.NewBroker(cfg, logger)
		if err != nil {
			t.Errorf("failed initializing broker driver %s: %v", driver, err)
		}
		if b.Driver != driver {
			t.Errorf("expected driver %s, got %s", driver, b.Driver)
		}
		if err := b.Ping(context.Background()); err != nil {
			t.Errorf("ping failed for driver %s: %v", driver, err)
		}
	}
}
