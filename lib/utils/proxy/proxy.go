/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"

	"golang.org/x/crypto/ssh"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentConnectProxy,
})

// NewClientConnWithDeadline establishes new client connection with specified deadline
func NewClientConnWithDeadline(conn net.Conn, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if config.Timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(config.Timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// DialWithDeadline works around the case when net.DialWithTimeout
// succeeds, but key exchange hangs. Setting deadline on connection
// prevents this case from happening
func DialWithDeadline(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}
	return NewClientConnWithDeadline(conn, addr, config)
}

// A Dialer is a means for a client to establish a SSH connection.
type Dialer interface {
	// Dial establishes a client connection to a SSH server.
	Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error)

	// DialTimeout acts like Dial but takes a timeout.
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

type directDial struct{}

// Dial calls ssh.Dial directly.
func (d directDial) Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return DialWithDeadline(network, addr, config)
}

// DialTimeout acts like Dial but takes a timeout.
func (d directDial) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

type proxyDial struct {
	proxyURL      *url.URL
	cloudProxyURL *url.URL
}

// DialTimeout acts like Dial but takes a timeout.
func (d proxyDial) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	// Build a proxy connection first.
	ctx := context.Background()
	if timeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ctx = timeoutCtx
	}
	return dialProxy(ctx, d.proxyURL, d.cloudProxyURL, address)
}

// Dial first connects to a proxy, then uses the connection to establish a new
// SSH connection.
func (d proxyDial) Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	// Build a proxy connection first.
	pconn, err := dialProxy(context.Background(), d.proxyURL, d.cloudProxyURL, addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if config.Timeout > 0 {
		pconn.SetReadDeadline(time.Now().Add(config.Timeout))
	}
	// Do the same as ssh.Dial but pass in proxy connection.
	c, chans, reqs, err := ssh.NewClientConn(pconn, addr, config)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if config.Timeout > 0 {
		pconn.SetReadDeadline(time.Time{})
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// DialerFromEnvironment returns a Dial function. If the https_proxy or http_proxy
// environment variable are set, it returns a function that will dial through
// said proxy server. If neither variable is set, it will connect to the SSH
// server directly.
func DialerFromEnvironment(addr string) Dialer {
	// Try and get proxy addr from the environment.
	proxyAddr := getProxyAddress(addr)
	cloudProxyAddr := getCloudProxyAddress()

	// If no proxy settings are in environment return regular ssh dialer,
	// otherwise return a proxy dialer.
	if proxyAddr == nil && cloudProxyAddr == nil {
		log.Debugf("No proxies set in environment, returning direct dialer.")
		return directDial{}
	}

	log.Debugf("Found proxies %q, %q in environment, returning proxy dialer.", proxyAddr, cloudProxyAddr)
	return proxyDial{proxyURL: proxyAddr, cloudProxyURL: cloudProxyAddr}
}

func dialProxy(ctx context.Context, proxyURL, cloudProxyURL *url.URL, addr string) (net.Conn, error) {
	var err error
	var conn net.Conn

	if proxyURL == nil {
		log.Warnln("Unable to dial to proxy, proxyaddr is nil")
		return dialCloudProxy(ctx, conn, cloudProxyURL, addr)
	}

	switch proxyURL.Scheme {
	// case "https":
	// 	conn, err = tls.Dial("tcp", proxyURL.Host, &tls.Config{})
	default:
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", proxyURL.Host)
	}
	if err != nil {
		log.Warnf("Unable to dial to proxy: %v: %v.", proxyURL, err)
		return nil, trace.ConvertSystemError(err)
	}

	var targetAddr string
	if cloudProxyURL == nil {
		targetAddr = addr
	} else {
		targetAddr = cloudProxyURL.Host
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	err = connectReq.Write(conn)
	if err != nil {
		log.Warnf("Unable to write to proxy: %v.", err)
		return nil, trace.Wrap(err)
	}

	// Read in the response. http.ReadResponse will read in the status line, mime
	// headers, and potentially part of the response body. the body itself will
	// not be read, but kept around so it can be read later.
	br := bufio.NewReader(conn)
	// Per the above comment, we're only using ReadResponse to check the status
	// and then hand off the underlying connection to the caller.
	// resp.Body.Close() would drain conn and close it, we don't need to do it
	// here. Disabling bodyclose linter for this edge case.
	//nolint:bodyclose
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		log.Warnf("Unable to read response: %v.", err)
		return nil, trace.Wrap(err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, trace.BadParameter("unable to proxy connection: %v", resp.Status)
	}

	proxyconn := &bufferedConn{
		Conn:   conn,
		reader: br,
	}

	if cloudProxyURL == nil {
		return proxyconn, nil
	}

	return dialCloudProxy(ctx, proxyconn, cloudProxyURL, addr)
}

func dialCloudProxy(ctx context.Context, conn net.Conn, cloudProxyURL *url.URL, addr string) (net.Conn, error) {
	var err error
	log.Debugf("[dialCloudProxy] cloudProxy:%v, conn:%v, addr:%v", cloudProxyURL, conn, addr)

	// if cloudProxyURL is nil, return conn from dialProxy
	if cloudProxyURL == nil {
		log.Warnln("Unable to dial to cloud proxy, cloudProxyAddr is nil")
		return conn, nil
	}

	// if connection is nil, create new connection for cloud proxy
	if conn == nil {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", cloudProxyURL.Host)
	}
	if err != nil {
		log.Warnf("Unable to dial to cloud proxy: %v: %v.", cloudProxyURL, err)
		return nil, trace.ConvertSystemError(err)
	}
	// if cloud proxy has https scheme, need to update connect till tls
	if cloudProxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: cloudProxyURL.Hostname(),
		})

		conn = tlsConn
	}

	// doing one more hop over the existing connection to proxy
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	err = connectReq.Write(conn)
	if err != nil {
		log.Warnf("Unable to write to cloud proxy: %v.", err)
		return nil, trace.Wrap(err)
	}

	// Read in the response. http.ReadResponse will read in the status line, mime
	// headers, and potentially part of the response body. the body itself will
	// not be read, but kept around so it can be read later.
	br := bufio.NewReader(conn)
	// Per the above comment, we're only using ReadResponse to check the status
	// and then hand off the underlying connection to the caller.
	// resp.Body.Close() would drain conn and close it, we don't need to do it
	// here. Disabling bodyclose linter for this edge case.
	//nolint:bodyclose
	cloudresp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		log.Warnf("Unable to read cloud  response: %v.", err)
		return nil, trace.Wrap(err)
	}
	if cloudresp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, trace.BadParameter("unable to cloud proxy connection: %v", cloudresp.Status)
	}

	// Return a bufferedConn that wraps a net.Conn and a *bufio.Reader. this
	// needs to be done because http.ReadResponse will buffer part of the
	// response body in the *bufio.Reader that was passed in. reads must first
	// come from anything buffered, then from the underlying connection otherwise
	// data will be lost.
	return &bufferedConn{
		Conn:   conn,
		reader: br,
	}, nil
}

func getProxyAddress(addr string) *url.URL {
	envs := []string{
		teleport.HTTPSProxy,
		strings.ToLower(teleport.HTTPSProxy),
		teleport.HTTPProxy,
		strings.ToLower(teleport.HTTPProxy),
	}

	for _, v := range envs {
		envAddr := os.Getenv(v)
		if envAddr == "" {
			continue
		}
		proxyAddr, err := parse(envAddr)
		if err != nil {
			log.Debugf("Unable to parse environment variable %q: %q.", v, envAddr)
			continue
		}
		log.Debugf("Successfully parsed environment variable %q: %q to %q.", v, envAddr, proxyAddr)
		if !useProxy(addr) {
			log.Debugf("Matched NO_PROXY override for %q: %q, going to ignore proxy variable.", v, envAddr)
			return nil
		}
		return proxyAddr
	}

	log.Debugf("No valid environment variables found.")
	return nil
}

func getCloudProxyAddress() *url.URL {
	envAddr := os.Getenv("CLOUD_PROXY")
	if envAddr == "" {
		log.Debugf("No valid CLOUD_PROXY variable found.")
		return nil
	}
	cloudProxyAddr, err := parse(envAddr)
	if err != nil {
		log.Debugf("Unable to parse CLOUD_PROXY environment: %q.", cloudProxyAddr)
		return nil
	}

	log.Debugf("Successfully parsed CLOUD_PROXY environment: %q to %q.", envAddr, cloudProxyAddr)
	return cloudProxyAddr
}

// parse will extract the host:port of the proxy to dial to. If the
// value is not prefixed by "http", then it will prepend "http" and try.
func parse(addr string) (*url.URL, error) {
	proxyurl, err := url.Parse(addr)
	if err != nil || !strings.HasPrefix(proxyurl.Scheme, "http") {
		proxyurl, err = url.Parse("http://" + addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return proxyurl, nil
}

// bufferedConn is used when part of the data on a connection has already been
// read by a *bufio.Reader. Reads will first try and read from the
// *bufio.Reader and when everything has been read, reads will go to the
// underlying connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read first reads from the *bufio.Reader any data that has already been
// buffered. Once all buffered data has been read, reads go to the net.Conn.
func (bc *bufferedConn) Read(b []byte) (n int, err error) {
	if bc.reader.Buffered() > 0 {
		return bc.reader.Read(b)
	}
	return bc.Conn.Read(b)
}
