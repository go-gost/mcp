package egress

import (
	"fmt"

	"github.com/go-gost/mcp/internal/config"
)

// Profile describes one built egress without exposing the chain.
type Profile struct {
	Name        string
	Description string
}

// Registry holds every egress from one config, keyed by name and preserving
// declaration order.
type Registry struct {
	byName map[string]*Egress
	order  []string
}

// BuildAll builds every profile. A duplicate name fails the whole registry:
// names are how tools select an egress, so they must be unambiguous.
func BuildAll(profiles []config.EgressProfile) (*Registry, error) {
	r := &Registry{byName: make(map[string]*Egress, len(profiles))}
	for i := range profiles {
		e, err := Build(&profiles[i])
		if err != nil {
			return nil, err
		}
		if _, ok := r.byName[e.Name]; ok {
			return nil, fmt.Errorf("egress %q: duplicate profile name", e.Name)
		}
		r.byName[e.Name] = e
		r.order = append(r.order, e.Name)
	}
	return r, nil
}

// Get returns the named egress.
func (r *Registry) Get(name string) (*Egress, bool) {
	if r == nil {
		return nil, false
	}
	e, ok := r.byName[name]
	return e, ok
}

// Profiles returns the built profiles in declaration order.
func (r *Registry) Profiles() []Profile {
	if r == nil {
		return nil
	}
	out := make([]Profile, 0, len(r.order))
	for _, name := range r.order {
		e := r.byName[name]
		out = append(out, Profile{Name: e.Name, Description: e.Description})
	}
	return out
}
