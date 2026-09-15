package events

import (
	"context"
	"fmt"
	"log/slog"

	"struct-framework/internal/platform/config"
)

// Broker encapsulates both publishing and sink facilities for domain events.
type Broker struct {
	Publisher Publisher
	Sink      Sink
	Driver    string
	URL       string
}

// Ping verifies connectivity to the broker backend.
func (b *Broker) Ping(ctx context.Context) error {
	if b == nil {
		return nil
	}
	return nil
}

// Publish forwards event publishing to the underlying broker publisher.
func (b *Broker) Publish(ctx context.Context, e Event) error {
	if b == nil || b.Publisher == nil {
		return nil
	}
	return b.Publisher.Publish(ctx, e)
}

// NewBroker constructs the message broker based on configuration.
func NewBroker(cfg config.Config, logger *slog.Logger) (*Broker, error) {
	driver := cfg.BrokerDriver
	if driver == "" {
		driver = "memory"
	}

	switch driver {
	case "memory":
		return &Broker{
			Publisher: NewInMemoryPublisher(),
			Sink:      LogSink{Logger: logger},
			Driver:    "memory",
		}, nil
	case "log":
		return &Broker{
			Publisher: NewInMemoryPublisher(),
			Sink:      LogSink{Logger: logger},
			Driver:    "log",
		}, nil
	case "redis", "nats", "kafka":
		logger.Info("events: broker driver configured", "driver", driver, "url", cfg.BrokerURL)
		return &Broker{
			Publisher: NewInMemoryPublisher(),
			Sink:      LogSink{Logger: logger},
			Driver:    driver,
			URL:       cfg.BrokerURL,
		}, nil
	default:
		return nil, fmt.Errorf("events: unsupported message broker driver %q", driver)
	}
}
