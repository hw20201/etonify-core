//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityClientFallbackURL(t *testing.T) {
	t.Parallel()

	require.Equal(t, "https://example.com", realityClientFallbackURL("example.com", ""))
	require.Equal(t, "https://example.com/path", realityClientFallbackURL("example.com", "/path"))
	require.Equal(t, "https://example.com?ed=2560", realityClientFallbackURL("example.com", "?ed=2560"))
	require.Equal(t, "https://example.com/path", realityClientFallbackURL("example.com", "path"))
}

func TestRealityFallbackDisabledContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	require.False(t, realityFallbackDisabled(ctx))
	require.True(t, realityFallbackDisabled(WithRealityFallbackDisabled(ctx)))
	require.False(t, realityFallbackDisabled(ctx), "opt-in must not mutate the shared parent context")
}

func generateTestCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Co"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func TestRealityClientHandshake_MinClientVer(t *testing.T) {
	cert, err := generateTestCertificate()
	require.NoError(t, err)

	decoyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "example.com",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	decoyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer decoyListener.Close()

	go func() {
		for {
			conn, err := decoyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := tls.Server(c, decoyTLSConfig)
				_ = s.Handshake()
			}(conn)
		}
	}()

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	shortID := [8]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	serverConfig := &utls.RealityConfig{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", decoyListener.Addr().String())
		},
		ServerNames:  map[string]bool{"example.com": true},
		PrivateKey:   privKey.Bytes(),
		ShortIds:     map[[8]byte]bool{shortID: true},
		MinClientVer: []byte{26, 3, 27},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sConn, err := utls.RealityServer(context.Background(), conn, serverConfig)
		if err != nil {
			return
		}
		_ = sConn.Handshake()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	realityClient, err := newRealityClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes()),
			ShortID:   hex.EncodeToString(shortID[:]),
		},
	}, false)
	require.NoError(t, err)

	_, err = realityClient.Client(clientConn)
	require.NoError(t, err)
}

func TestRealityClientHandshake_MinClientVer_Rejection(t *testing.T) {
	cert, err := generateTestCertificate()
	require.NoError(t, err)

	decoyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "example.com",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	decoyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer decoyListener.Close()

	go func() {
		for {
			conn, err := decoyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := tls.Server(c, decoyTLSConfig)
				_ = s.Handshake()
			}(conn)
		}
	}()

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	shortID := [8]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	// Server requires version 27.0.0, higher than client's 26.9.9
	serverConfig := &utls.RealityConfig{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", decoyListener.Addr().String())
		},
		ServerNames:  map[string]bool{"example.com": true},
		PrivateKey:   privKey.Bytes(),
		ShortIds:     map[[8]byte]bool{shortID: true},
		MinClientVer: []byte{27, 0, 0},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sConn, err := utls.RealityServer(context.Background(), conn, serverConfig)
		if err != nil {
			return
		}
		_ = sConn.Handshake()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	realityClient, err := newRealityClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes()),
			ShortID:   hex.EncodeToString(shortID[:]),
		},
	}, false)
	require.NoError(t, err)

	_, err = realityClient.(*RealityClientConfig).ClientHandshake(WithRealityFallbackDisabled(context.Background()), clientConn)
	require.Error(t, err)
}

type fallbackRecordingConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (c *fallbackRecordingConn) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }
func (c *fallbackRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes += len(p)
	return len(p), nil
}
func (c *fallbackRecordingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (*fallbackRecordingConn) LocalAddr() net.Addr              { return fallbackRecordingAddr("local") }
func (*fallbackRecordingConn) RemoteAddr() net.Addr             { return fallbackRecordingAddr("remote") }
func (*fallbackRecordingConn) SetDeadline(time.Time) error      { return nil }
func (*fallbackRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*fallbackRecordingConn) SetWriteDeadline(time.Time) error { return nil }

type fallbackRecordingAddr string

func (a fallbackRecordingAddr) Network() string { return "test" }
func (a fallbackRecordingAddr) String() string  { return string(a) }

func TestRealityVerificationFailedFallbackPolicy(t *testing.T) {
	t.Run("opt-in disables fallback and closes without writing", func(t *testing.T) {
		conn := &fallbackRecordingConn{}
		fallbackCalled := make(chan struct{}, 1)
		err := realityVerificationFailed(WithRealityFallbackDisabled(context.Background()), conn, func() { fallbackCalled <- struct{}{} })
		require.EqualError(t, err, "reality verification failed")
		conn.mu.Lock()
		require.True(t, conn.closed)
		require.Zero(t, conn.writes)
		conn.mu.Unlock()
		select {
		case <-fallbackCalled:
			t.Fatal("fallback must not run")
		default:
		}
	})

	t.Run("default preserves asynchronous fallback", func(t *testing.T) {
		conn := &fallbackRecordingConn{}
		fallbackCalled := make(chan struct{})
		err := realityVerificationFailed(context.Background(), conn, func() {
			defer close(fallbackCalled)
			_ = conn.Close() // Simulate completion/cleanup by the ordinary background fallback.
		})
		require.EqualError(t, err, "reality verification failed")
		select {
		case <-fallbackCalled:
		case <-time.After(time.Second):
			t.Fatal("default fallback was not started")
		}
		conn.mu.Lock()
		require.True(t, conn.closed)
		require.Zero(t, conn.writes)
		conn.mu.Unlock()
	})
}
