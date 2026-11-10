package portmap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UPnP IGD: find the router with SSDP, read its device description, then
// call WANIPConnection (or WANPPPConnection) over SOAP.

const ssdpDefault = "239.255.255.250:1900"

// Services that can forward a port, best first.
var upnpServices = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

var ssdpTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
}

func ssdpSearch(st string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " + st + "\r\n\r\n")
}

// parseSSDP returns the LOCATION of an SSDP answer that came from src. The
// description must be served by the host that answered, so another device
// on the LAN can't point the agent somewhere else.
func parseSSDP(b []byte, src netip.Addr) (*url.URL, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SSDP status %d", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" {
		return nil, errors.New("SSDP location is not http")
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap() != src.Unmap() {
		return nil, errors.New("SSDP location is not on the host that answered")
	}
	return u, nil
}

func (m *Mapper) discover(ctx context.Context, gw netip.Addr) (*url.URL, error) {
	target := m.SSDPAddr
	if target == "" {
		target = ssdpDefault
	}
	dst, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	for _, st := range ssdpTargets {
		if _, err := c.WriteToUDP(ssdpSearch(st), dst); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(ssdpWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetReadDeadline(deadline)
	var other *url.URL
	buf := make([]byte, 4096)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		u, err := parseSSDP(buf[:n], from.Addr())
		if err != nil {
			continue
		}
		if from.Addr().Unmap() == gw {
			return u, nil
		}
		if other == nil {
			other = u
		}
	}
	if other != nil {
		return other, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("no UPnP gateway answered")
}

type xmlDevice struct {
	Services []struct {
		Type    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []xmlDevice `xml:"deviceList>device"`
}

type xmlRoot struct {
	Base   string    `xml:"URLBase"`
	Device xmlDevice `xml:"device"`
}

// findService picks the best port-forwarding service in a device
// description and resolves its control URL against loc. The control URL
// must stay on loc's host.
func findService(desc []byte, loc *url.URL) (control, service string, err error) {
	var root xmlRoot
	if err := xml.Unmarshal(desc, &root); err != nil {
		return "", "", fmt.Errorf("device description: %w", err)
	}
	found := map[string]string{}
	var walk func(d *xmlDevice, depth int)
	walk = func(d *xmlDevice, depth int) {
		if depth > 8 {
			return
		}
		for _, s := range d.Services {
			t := strings.TrimSpace(s.Type)
			if _, ok := found[t]; !ok {
				found[t] = strings.TrimSpace(s.Control)
			}
		}
		for i := range d.Devices {
			walk(&d.Devices[i], depth+1)
		}
	}
	walk(&root.Device, 0)
	base := loc
	if b := strings.TrimSpace(root.Base); b != "" {
		if bu, err := url.Parse(b); err == nil {
			base = loc.ResolveReference(bu)
		}
	}
	for _, t := range upnpServices {
		ctl, ok := found[t]
		if !ok || ctl == "" {
			continue
		}
		cu, err := url.Parse(ctl)
		if err != nil {
			continue
		}
		cu = base.ResolveReference(cu)
		if cu.Scheme != "http" || cu.Host != loc.Host {
			continue
		}
		return cu.String(), t, nil
	}
	return "", "", errors.New("no WANIPConnection or WANPPPConnection service")
}

// soapError is a UPnP error from a SOAP fault.
type soapError struct {
	Code int
	Desc string
}

func (e *soapError) Error() string { return fmt.Sprintf("UPnP error %d %s", e.Code, e.Desc) }

// UPnP error codes worth acting on.
const (
	upnpConflict      = 718 // ConflictInMappingEntry
	upnpOnlyPermanent = 725 // OnlyPermanentLeasesSupported
)

type arg struct{ k, v string }

func soapBody(service, action string, args []arg) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>` + "\r\n" +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="`)
	_ = xml.EscapeText(&b, []byte(service))
	b.WriteString(`">`)
	for _, a := range args {
		b.WriteString("<" + a.k + ">")
		_ = xml.EscapeText(&b, []byte(a.v))
		b.WriteString("</" + a.k + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	return b.Bytes()
}

// soapValues collects the text of each leaf element by local name.
func soapValues(body []byte) (map[string]string, error) {
	out := map[string]string{}
	d := xml.NewDecoder(bytes.NewReader(body))
	var cur string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
		case xml.CharData:
			if cur != "" {
				out[cur] += string(t)
			}
		case xml.EndElement:
			cur = ""
		}
	}
}

func (m *Mapper) soap(ctx context.Context, control, service, action string, args []arg) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", control, bytes.NewReader(soapBody(service, action, args)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+service+"#"+action+`"`)
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	vals, perr := soapValues(body)
	if resp.StatusCode != http.StatusOK {
		if perr == nil {
			if code, err := strconv.Atoi(strings.TrimSpace(vals["errorCode"])); err == nil {
				return nil, &soapError{Code: code, Desc: strings.TrimSpace(vals["errorDescription"])}
			}
		}
		return nil, fmt.Errorf("UPnP %s: HTTP %d", action, resp.StatusCode)
	}
	if perr != nil {
		return nil, fmt.Errorf("UPnP %s reply: %w", action, perr)
	}
	return vals, nil
}

func (m *Mapper) description() string {
	if m.Description != "" {
		return m.Description
	}
	return "wgh"
}

func randomPort() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return 32768 + binary.BigEndian.Uint16(b[:])%28000
}

func (m *Mapper) mapUPnP(ctx context.Context, gw netip.Addr, internal uint16, lifetime time.Duration) (Mapping, error) {
	loc, err := m.discover(ctx, gw)
	if err != nil {
		return Mapping{}, err
	}
	hctx, cancel := context.WithTimeout(ctx, httpTimeout)
	req, err := http.NewRequestWithContext(hctx, "GET", loc.String(), nil)
	if err != nil {
		cancel()
		return Mapping{}, err
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		cancel()
		return Mapping{}, err
	}
	desc, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	resp.Body.Close()
	cancel()
	if err != nil {
		return Mapping{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Mapping{}, fmt.Errorf("device description: HTTP %d", resp.StatusCode)
	}
	control, service, err := findService(desc, loc)
	if err != nil {
		return Mapping{}, err
	}
	// This device's address as the router sees it.
	host, _ := netip.ParseAddr(loc.Hostname())
	port := 80
	if p, err := strconv.Atoi(loc.Port()); err == nil {
		port = p
	}
	c, err := dial(ctx, host.Unmap(), port)
	if err != nil {
		return Mapping{}, err
	}
	client := localAddr(c)
	c.Close()

	_, last := m.state()
	ext := last
	if ext == 0 {
		ext = internal
	}
	lease := lifeSecs(lifetime)
	add := func(action string, ext uint16, lease uint32) (map[string]string, error) {
		return m.soap(ctx, control, service, action, []arg{
			{"NewRemoteHost", ""},
			{"NewExternalPort", strconv.Itoa(int(ext))},
			{"NewProtocol", "UDP"},
			{"NewInternalPort", strconv.Itoa(int(internal))},
			{"NewInternalClient", client.String()},
			{"NewEnabled", "1"},
			{"NewPortMappingDescription", m.description()},
			{"NewLeaseDuration", strconv.Itoa(int(lease))},
		})
	}
	_, err = add("AddPortMapping", ext, lease)
	var se *soapError
	if errors.As(err, &se) && se.Code == upnpOnlyPermanent {
		lease = 0 // removed by Unmap instead
		_, err = add("AddPortMapping", ext, lease)
	}
	if err != nil && ctx.Err() == nil {
		// The port is taken (or refused): let the router choose, or pick one.
		if strings.HasSuffix(service, "WANIPConnection:2") {
			var vals map[string]string
			if vals, err = add("AddAnyPortMapping", ext, lease); err == nil {
				p, perr := strconv.Atoi(strings.TrimSpace(vals["NewReservedPort"]))
				if perr != nil || p <= 0 || p > 65535 {
					err = errors.New("UPnP AddAnyPortMapping: bad reserved port")
				} else {
					ext = uint16(p)
				}
			}
		} else if errors.As(err, &se) && se.Code == upnpConflict {
			ext = randomPort()
			_, err = add("AddPortMapping", ext, lease)
		}
	}
	if err != nil {
		return Mapping{}, err
	}
	mp := Mapping{Protocol: ProtoUPnP, Expires: m.now().Add(lifetime), gateway: gw, internal: internal,
		control: control, service: service}
	mp.External = netip.AddrPortFrom(netip.IPv4Unspecified(), ext)
	vals, err := m.soap(ctx, control, service, "GetExternalIPAddress", nil)
	if err != nil {
		_ = m.unmapUPnP(context.WithoutCancel(ctx), mp)
		return Mapping{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(vals["NewExternalIPAddress"]))
	if err != nil {
		_ = m.unmapUPnP(context.WithoutCancel(ctx), mp)
		return Mapping{}, fmt.Errorf("UPnP external address %q", vals["NewExternalIPAddress"])
	}
	if !Usable(ip) {
		_ = m.unmapUPnP(context.WithoutCancel(ctx), mp)
		return Mapping{}, doubleNAT(ProtoUPnP, ip)
	}
	mp.External = netip.AddrPortFrom(ip.Unmap(), ext)
	return mp, nil
}

func (m *Mapper) unmapUPnP(ctx context.Context, mp Mapping) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := m.soap(ctx, mp.control, mp.service, "DeletePortMapping", []arg{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(mp.External.Port()))},
		{"NewProtocol", "UDP"},
	})
	return err
}
