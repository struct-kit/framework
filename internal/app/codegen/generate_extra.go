package codegen

import "fmt"

// Policy generates a deny-by-default authz.Policy implementation plus its
// unit test (framework guide §7.4, "struct make policy").
//
// Assumes the target project has internal/platform/security/authz present
// (the standard/full project templates include it).
func Policy(modulePath, name string) (implPath, implSource, testPath, testSource string) {
	pascal := Pascal(name)
	snake := Snake(name)
	implPath = fmt.Sprintf("internal/platform/security/authz/%s_policy.go", snake)
	implSource = fmt.Sprintf(`package authz

import "context"

// %sPolicy is deny-by-default: Evaluate must return Allow explicitly for
// every case it means to permit. Anything it doesn't recognize falls
// through to the zero-value Deny at the bottom.
type %sPolicy struct{}

func New%sPolicy() *%sPolicy {
	return &%sPolicy{}
}

func (p *%sPolicy) Evaluate(ctx context.Context, subject Subject, action, resource string) Decision {
	// TODO: replace with real rules as this policy's requirements are known.
	// Example ownership check once resource IDs carry an owner:
	//   if action == "read" && subject.UserID == resourceOwnerID {
	//       return Allow
	//   }
	return Deny
}
`, pascal, pascal, pascal, pascal, pascal, pascal)

	testPath = fmt.Sprintf("internal/platform/security/authz/%s_policy_test.go", snake)
	testSource = fmt.Sprintf(`package authz

import (
	"context"
	"testing"
)

func Test%sPolicy_DeniesByDefault(t *testing.T) {
	p := New%sPolicy()
	subject := Subject{UserID: "someone", Roles: []string{"member"}}

	got := p.Evaluate(context.Background(), subject, "read", "some-resource")
	if got != Deny {
		t.Fatalf("expected Deny for an unrecognized case, got %%v", got)
	}
}
`, pascal, pascal)
	return implPath, implSource, testPath, testSource
}

// Event generates a versioned domain event type plus a consumer stub
// (framework guide §6.5, "struct make event").
//
// Assumes the target project has internal/platform/events present (the
// standard/full project templates include it). The real transactional
// outbox lands in Pass 6; this generates against events.Publisher, which
// Pass 6's outbox-backed implementation will satisfy without any change
// to generated call sites.
func Event(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/platform/events/%s_event.go", snake)
	source = fmt.Sprintf(`package events

import (
	"context"
	"time"
)

// %sV1 is the payload for the "%sV1" event. Only ever add optional
// fields to this version — a breaking change gets its own %sV2 (§6.5).
type %sV1 struct {
	AggregateID string
	OccurredAt  time.Time
}

const %sEventName = "%sV1"

func New%sEvent(aggregateID string) Event {
	return Event{
		Name:        %sEventName,
		AggregateID: aggregateID,
		OccurredAt:  time.Now().UTC(),
		Payload: %sV1{
			AggregateID: aggregateID,
			OccurredAt:  time.Now().UTC(),
		},
	}
}

// Publish%s publishes through pub. Every event carries a unique ID from
// the caller so consumers can de-duplicate on redelivery (§6.5) — this
// generator does not assign one, since ID generation policy (ULID, UUID,
// DB sequence) is a project-level decision.
func Publish%s(ctx context.Context, pub Publisher, e Event) error {
	return pub.Publish(ctx, e)
}
`, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal)
	return path, source
}

// Job generates a queue.Job implementation (framework guide §11,
// "struct make job").
//
// Assumes the target project has internal/support/queue present (the
// standard/full project templates include it).
func Job(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/support/queue/%s_job.go", snake)
	source = fmt.Sprintf(`package queue

import "context"

// %sJob implements Job. Wire its dependencies through the constructor —
// never reach for global state from inside Run.
type %sJob struct {
	// TODO: add this job's dependencies (a repository, a mailer, etc.)
}

func New%sJob() *%sJob {
	return &%sJob{}
}

func (j *%sJob) Name() string { return "%s" }

func (j *%sJob) Run(ctx context.Context) error {
	// TODO: implement the job. Return a non-nil error to trigger
	// InProcessRunner's retry/backoff (or a durable queue's, once one is
	// wired in) — never swallow an error here to "keep the job simple".
	return nil
}
`, pascal, pascal, pascal, pascal, pascal, pascal, snake, pascal)
	return path, source
}
