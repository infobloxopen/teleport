package services

import (
	"context"
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// Semaphores provides ability to control
// how many shared resources of some kind are acquired at the same time,
// used to implement concurrent sessions control in a distributed environment
type Semaphores interface {
	// TryAcquireSemaphore acquires lease with requested resources from semaphore
	AcquireSemaphore(ctx context.Context, sem Semaphore, l SemaphoreLease) (*SemaphoreLease, error)
	// KeepAliveSemaphoreLease updates semaphore lease
	KeepAliveSemaphoreLease(ctx context.Context, l SemaphoreLease) error
}

// NewSemaphore is a convenience wrapper to create a Semaphore
func NewSemaphore(name, subKind string, spec SemaphoreSpecV3) (Semaphore, error) {
	cc := SemaphoreV3{
		Kind:    KindSemaphore,
		SubKind: subKind,
		Version: V3,
		Metadata: Metadata{
			Name:      name,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}
	if err := cc.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &cc, nil
}

// Semaphore represents distributed semaphore concept
type Semaphore interface {
	// Resource contains common resource values
	Resource
	// CheckAndSetDefaults checks and sets default parameter
	CheckAndSetDefaults() error
	// GetMaxResources returns maximum available amount
	// of resources consumed by the semaphore
	GetMaxResources() int64
	// AddLease adds a lease to the list
	AddLease(SemaphoreLease)
	// SetLeases sets the lease list to the value
	SetLeases([]SemaphoreLease)
	// RemoveLease removes lease from the list
	RemoveLease(l SemaphoreLease) error
	// GetLeases returns all leases used by semaphore
	GetLeases() []SemaphoreLease
	// AcquiredResources computes and returns the amount of acquired resources
	AcquiredResources() int64
	// RemoveExpiredLeases removes expired leases
	RemoveExpiredLeases(time.Time)
}

// CheckAndSetDefaults checks and sets default values
func (l *SemaphoreLease) CheckAndSetDefaults() error {
	if l == nil {
		return trace.BadParameter("missing lease object")
	}
	if l.Resources <= 0 {
		return trace.BadParameter("parameter Resources should be >= 0")
	}
	if l.SemaphoreName == "" {
		return trace.BadParameter("missing parameter SemaphoreName")
	}
	if l.SemaphoreSubKind == "" {
		return trace.BadParameter("missing parameter SemaphoreSubKind")
	}
	if l.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	return nil
}

// RemoveExpiredLeases removes expired leases
func (c *SemaphoreV3) RemoveExpiredLeases(now time.Time) {
	// See https://github.com/golang/go/wiki/SliceTricks#filtering-without-allocating
	filtered := c.Spec.Leases[:0]
	for _, lease := range c.Spec.Leases {
		if lease.Expires.After(now) {
			filtered = append(filtered, lease)
		}
	}
	c.Spec.Leases = filtered
}

// AcquiredResources computes and returns the amount of acquired resources
func (c *SemaphoreV3) AcquiredResources() int64 {
	total := int64(0)
	for _, lease := range c.Spec.Leases {
		total += lease.Resources
	}
	return total
}

// AddLease adds a lease to the list
func (c *SemaphoreV3) AddLease(l SemaphoreLease) {
	c.Spec.Leases = append(c.Spec.Leases, l)
}

// SetLeases sets leases list
func (c *SemaphoreV3) SetLeases(l []SemaphoreLease) {
	c.Spec.Leases = l
}

// RemoveLease removes lease from the list
func (c *SemaphoreV3) RemoveLease(l SemaphoreLease) error {
	for i := range c.Spec.Leases {
		if c.Spec.Leases[i].ID == l.ID {
			c.Spec.Leases = append(c.Spec.Leases[:i], c.Spec.Leases[i+1:]...)
			return nil
		}
	}
	return trace.NotFound("lease %v is not found", l.ID)
}

// GetLeases returns all leases used by semaphore
func (c *SemaphoreV3) GetLeases() []SemaphoreLease {
	return c.Spec.Leases
}

func (c *SemaphoreV3) GetMaxResources() int64 {
	return c.Spec.MaxResources
}

// GetVersion returns resource version
func (c *SemaphoreV3) GetVersion() string {
	return c.Version
}

// GetSubKind returns resource subkind
func (c *SemaphoreV3) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind
func (c *SemaphoreV3) SetSubKind(sk string) {
	c.SubKind = sk
}

// GetKind returns resource kind
func (c *SemaphoreV3) GetKind() string {
	return c.Kind
}

// GetResourceID returns resource ID
func (c *SemaphoreV3) GetResourceID() int64 {
	return c.Metadata.ID
}

// SetResourceID sets resource ID
func (c *SemaphoreV3) SetResourceID(id int64) {
	c.Metadata.ID = id
}

// GetName returns the name of the cluster.
func (c *SemaphoreV3) GetName() string {
	return c.Metadata.Name
}

// SetName sets the name of the cluster.
func (c *SemaphoreV3) SetName(e string) {
	c.Metadata.Name = e
}

// Expires returns object expiry setting
func (c *SemaphoreV3) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// SetExpiry sets expiry time for the object
func (c *SemaphoreV3) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// SetTTL sets Expires header using realtime clock
func (c *SemaphoreV3) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	c.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata
func (c *SemaphoreV3) GetMetadata() Metadata {
	return c.Metadata
}

// String represents a human readable version of the semaphore.
func (c *SemaphoreV3) String() string {
	return fmt.Sprintf("Semaphore(%v, subKind=%v, maxResources=%v)",
		c.Metadata.Name, c.SubKind, c.Spec.MaxResources)
}

// CheckAndSetDefaults checks validity of all parameters and sets defaults.
func (c *SemaphoreV3) CheckAndSetDefaults() error {
	// make sure we have defaults for all metadata fields
	err := c.Metadata.CheckAndSetDefaults()
	if err != nil {
		return trace.Wrap(err)
	}
	if c.SubKind == "" {
		return trace.BadParameter("supply semaphore SubKind parameter")
	}
	return nil
}

// SemaphoreSpecSchemaTemplate is a template for Semaphore schema.
const SemaphoreSpecSchemaTemplate = `{
  "type": "object",
  "additionalProperties": true,
  "properties": {
  }
}`

// GetSemaphoreSchema returns the validattion schema for this object
func GetSemaphoreSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, SemaphoreSpecSchemaTemplate, DefaultDefinitions)
}

// SemaphoreMarshaler implements marshal/unmarshal of Semaphore implementations
// mostly adds support for extended versions.
type SemaphoreMarshaler interface {
	Marshal(c Semaphore, opts ...MarshalOption) ([]byte, error)
	Unmarshal(bytes []byte, opts ...MarshalOption) (Semaphore, error)
}

var semaphoreMarshaler SemaphoreMarshaler = &TeleportSemaphoreMarshaler{}

// SetSemaphoreMarshaler sets the marshaler.
func SetSemaphoreMarshaler(m SemaphoreMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	semaphoreMarshaler = m
}

// GetSemaphoreMarshaler gets the marshaler.
func GetSemaphoreMarshaler() SemaphoreMarshaler {
	marshalerMutex.RLock()
	defer marshalerMutex.RUnlock()
	return semaphoreMarshaler
}

// TeleportSemaphoreMarshaler is used to marshal and unmarshal Semaphore.
type TeleportSemaphoreMarshaler struct{}

// Unmarshal unmarshals Semaphore from JSON.
func (t *TeleportSemaphoreMarshaler) Unmarshal(bytes []byte, opts ...MarshalOption) (Semaphore, error) {
	var semaphore SemaphoreV3

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &semaphore); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err = utils.UnmarshalWithSchema(GetSemaphoreSchema(), &semaphore, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}

	err = semaphore.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.ID != 0 {
		semaphore.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		semaphore.SetExpiry(cfg.Expires)
	}
	return &semaphore, nil
}

// Marshal marshals Semaphore to JSON.
func (t *TeleportSemaphoreMarshaler) Marshal(c Semaphore, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch resource := c.(type) {
	case *SemaphoreV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *resource
			copy.SetResourceID(0)
			resource = &copy
		}
		return utils.FastMarshal(resource)
	default:
		return nil, trace.BadParameter("unrecognized resource version %T", c)
	}
}
