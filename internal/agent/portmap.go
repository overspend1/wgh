package agent

import (
	"context"
	"errors"
	"time"

	"github.com/overspend1/wgh/internal/portmap"
)

// PortMapper asks the router to forward the WireGuard port; *portmap.Mapper
// is the real one.
type PortMapper interface {
	Map(ctx context.Context, internalPort int, lifetime time.Duration) (portmap.Mapping, error)
	Unmap(ctx context.Context, m portmap.Mapping) error
}

// PortMapLifetime is how long each mapping is asked for; it is renewed at
// half that.
const PortMapLifetime = 2 * time.Hour

// Port-mapping states shown in status.
const (
	portMapOff       = "off"
	portMapSearching = "searching"
	portMapNone      = "none found"
)

func portMapNote(err error) string {
	switch {
	case errors.Is(err, portmap.ErrDoubleNAT):
		return portmap.ErrDoubleNAT.Error()
	case errors.Is(err, portmap.ErrNoGateway):
		return portMapNone + " (no default gateway)"
	}
	return portMapNone
}

// setMapped records the mapped endpoint and, when it changed, sends a
// heartbeat at once so the others learn it.
func (a *Agent) setMapped(endpoint, note string) {
	a.mu.Lock()
	changed := a.mapped != endpoint
	a.mapped, a.portMap = endpoint, note
	a.mu.Unlock()
	if changed {
		select {
		case a.hbWake <- struct{}{}:
		default:
		}
	}
}

// portMapLoop keeps a port mapped on the router while ctx lives, then
// removes it. It logs the first success and the first failure only.
func (a *Agent) portMapLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	pm := a.o.PortMapper
	if pm == nil {
		pm = &portmap.Mapper{Now: a.o.Now}
	}
	retry := a.o.PortMapRetry
	if retry == 0 {
		retry = time.Minute
	}
	backoff := retry
	var cur *portmap.Mapping
	loggedOK, loggedFail := false, false
	for {
		a.mu.Lock()
		port := a.st.ListenPort
		a.mu.Unlock()
		m, err := pm.Map(ctx, port, PortMapLifetime)
		if ctx.Err() != nil {
			if err == nil {
				cur = &m
			}
			break
		}
		var wait time.Duration
		if err != nil {
			if !loggedFail {
				a.o.Logf("portmap: %v (retrying quietly)", err)
				loggedFail = true
			}
			if cur != nil && a.o.Now().Before(cur.Expires) {
				// The old mapping still holds for a while: keep it.
				a.setMapped(cur.External.String(), cur.Protocol+" "+cur.External.String()+" (renewal failed)")
			} else {
				cur = nil
				a.setMapped("", portMapNote(err))
			}
			wait = backoff
			backoff = min(backoff*2, 30*time.Minute)
		} else {
			if cur == nil || cur.External != m.External {
				if !loggedOK || cur != nil {
					a.o.Logf("portmap: %s forwards %s to UDP port %d", m.Protocol, m.External, port)
				}
				loggedOK = true
			}
			if cur != nil && cur.Protocol != m.Protocol {
				uctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_ = pm.Unmap(uctx, *cur)
				cancel()
			}
			cur = &m
			a.setMapped(m.External.String(), m.Protocol+" "+m.External.String())
			backoff = retry
			wait = max(m.Expires.Sub(a.o.Now())/2, time.Second)
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		if ctx.Err() != nil {
			break
		}
	}
	if cur != nil {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		if err := pm.Unmap(uctx, *cur); err != nil {
			a.o.Logf("portmap: remove %s mapping: %v", cur.Protocol, err)
		}
		cancel()
	}
	a.setMapped("", portMapOff)
}

// startPortMap starts the loop when port mapping is on; the returned
// function stops it and waits for the mapping to be removed.
func (a *Agent) startPortMap(ctx context.Context) func() {
	if !a.o.PortMap {
		return func() {}
	}
	if a.o.DryRun {
		a.o.Logf("[dry-run] portmap: would ask the router (PCP, NAT-PMP or UPnP) to forward UDP port %d and tell the coordinator", a.st.ListenPort)
		a.mu.Lock()
		a.portMap = portMapOff + " (dry run)"
		a.mu.Unlock()
		return func() {}
	}
	a.mu.Lock()
	a.portMap = portMapSearching
	a.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go a.portMapLoop(ctx, done)
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}
