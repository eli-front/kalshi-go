package client 

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type Environment string

const (
	EnvironmentDemo Environment = "demo"
	EnvironmentProd Environment = "prod"
)

type KalshiBaseClient struct {
	keyID      string
	privateKey *rsa.PrivateKey
	environment Environment

	HTTPBaseURL string
	WSBaseURL   string

	lastAPICall atomic.Int64 // store Unix nano timestamp
}

func NewKalshiBaseClient(keyID string, priv *rsa.PrivateKey, env Environment) (*KalshiBaseClient, error) {
	c := &KalshiBaseClient{
		keyID:       keyID,
		privateKey:  priv,
		environment: env,
	}
	switch env {
	case EnvironmentDemo:
		c.HTTPBaseURL = "https://demo-api.kalshi.co"
		c.WSBaseURL = "wss://demo-api.kalshi.co"
	case EnvironmentProd:
		c.HTTPBaseURL = "https://api.elections.kalshi.com"
		c.WSBaseURL = "wss://api.elections.kalshi.com"
	default:
		return nil, fmt.Errorf("invalid environment")
	}
	c.lastAPICall.Store(time.Now().UnixNano())
	return c, nil
}

func (c *KalshiBaseClient) requestHeaders(method, path string) http.Header {
	nowMillis := time.Now().UnixMilli()
	ts := fmt.Sprintf("%d", nowMillis)

	// remove query parameters from the path
	pathOnly := path
	if idx := strings.Index(path, "?"); idx >= 0 {
		pathOnly = path[:idx]
	}

	msg := ts + strings.ToUpper(method) + pathOnly
	sig, _ := c.signPSS(msg)

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("KALSHI-ACCESS-KEY", c.keyID)
	h.Set("KALSHI-ACCESS-SIGNATURE", sig)
	h.Set("KALSHI-ACCESS-TIMESTAMP", ts)
	return h
}

func (c *KalshiBaseClient) signPSS(text string) (string, error) {
	hashed := sha256.Sum256([]byte(text))
	sig, err := rsa.SignPSS(rand.Reader, c.privateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("rsa sign pss failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Simple rate limiter, sleep if the last call was within 100 ms
func (c *KalshiBaseClient) rateLimit() {
	const threshold = 100 * time.Millisecond
	last := time.Unix(0, c.lastAPICall.Load())
	now := time.Now()
	if since := now.Sub(last); since < threshold {
		time.Sleep(threshold - since)
	}
	c.lastAPICall.Store(time.Now().UnixNano())
}

// ---------- HTTP client ----------

type KalshiHTTPClient struct {
	*KalshiBaseClient
	httpClient   *http.Client
	exchangePath string
	marketsPath  string
	portfolioPath string
}

func NewKalshiHTTPClient(keyID string, priv *rsa.PrivateKey, env Environment) (*KalshiHTTPClient, error) {
	base, err := NewKalshiBaseClient(keyID, priv, env)
	if err != nil {
		return nil, err
	}
	return &KalshiHTTPClient{
		KalshiBaseClient: base,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		exchangePath:     "/trade-api/v2/exchange",
		marketsPath:      "/trade-api/v2/markets",
		portfolioPath:    "/trade-api/v2/portfolio",
	}, nil
}

func (c *KalshiHTTPClient) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	c.rateLimit()

	u := c.HTTPBaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	for k, vals := range c.requestHeaders(method, path) {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http error, status %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *KalshiHTTPClient) Post(ctx context.Context, path string, body any, out any) error {
	return c.doJSON(ctx, http.MethodPost, path, nil, body, out)
}

func (c *KalshiHTTPClient) Get(ctx context.Context, path string, params map[string]any, out any) error {
	q := url.Values{}
	for k, v := range params {
		if v == nil {
			continue
		}
		q.Set(k, fmt.Sprintf("%v", v))
	}
	return c.doJSON(ctx, http.MethodGet, path, q, nil, out)
}

func (c *KalshiHTTPClient) Delete(ctx context.Context, path string, params map[string]any, out any) error {
	q := url.Values{}
	for k, v := range params {
		if v == nil {
			continue
		}
		q.Set(k, fmt.Sprintf("%v", v))
	}
	return c.doJSON(ctx, http.MethodDelete, path, q, nil, out)
}

// Convenience wrappers

func (c *KalshiHTTPClient) GetBalance(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.Get(ctx, c.portfolioPath+"/balance", nil, &out)
	return out, err
}

func (c *KalshiHTTPClient) GetExchangeStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.Get(ctx, c.exchangePath+"/status", nil, &out)
	return out, err
}

type TradesResponse map[string]any

func (c *KalshiHTTPClient) GetTrades(ctx context.Context, ticker *string, limit *int, cursor *string, maxTS *int64, minTS *int64) (TradesResponse, error) {
	params := map[string]any{}
	if ticker != nil {
		params["ticker"] = *ticker
	}
	if limit != nil {
		params["limit"] = *limit
	}
	if cursor != nil {
		params["cursor"] = *cursor
	}
	if maxTS != nil {
		params["max_ts"] = *maxTS
	}
	if minTS != nil {
		params["min_ts"] = *minTS
	}
	var out TradesResponse
	err := c.Get(ctx, c.marketsPath+"/trades", params, &out)
	return out, err
}

// ---------- WebSocket client ----------

type KalshiWebSocketClient struct {
	*KalshiBaseClient
	conn       *websocket.Conn
	urlSuffix  string
	messageID  int64
}

func NewKalshiWebSocketClient(keyID string, priv *rsa.PrivateKey, env Environment) (*KalshiWebSocketClient, error) {
	base, err := NewKalshiBaseClient(keyID, priv, env)
	if err != nil {
		return nil, err
	}
	return &KalshiWebSocketClient{
		KalshiBaseClient: base,
		urlSuffix:        "/trade-api/ws/v2",
		messageID:        1,
	}, nil
}

func (c *KalshiWebSocketClient) Connect(ctx context.Context) error {
	u := c.WSBaseURL + c.urlSuffix

	dialer := websocket.Dialer{
		HandshakeTimeout:  20 * time.Second,
		EnableCompression: true,
	}

	// Prepare headers for auth
	hdr := c.requestHeaders(http.MethodGet, c.urlSuffix)

	conn, _, err := dialer.DialContext(ctx, u, hdr)
	if err != nil {
		return err
	}
	c.conn = conn

	if err := c.onOpen(ctx); err != nil {
		_ = c.conn.Close()
		return err
	}

	// Start read loop
	go c.readLoop()

	return nil
}

func (c *KalshiWebSocketClient) onOpen(ctx context.Context) error {
	fmt.Println("WebSocket connection opened.")
	return c.subscribeToTickers()
}

func (c *KalshiWebSocketClient) subscribeToTickers() error {
	msg := map[string]any{
		"id":  atomic.AddInt64(&c.messageID, 1),
		"cmd": "subscribe",
		"params": map[string]any{
			"channels": []string{"ticker"},
		},
	}
	return c.writeJSON(msg)
}

func (c *KalshiWebSocketClient) writeJSON(v any) error {
	if c.conn == nil {
		return errors.New("websocket not connected")
	}
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(v)
}

func (c *KalshiWebSocketClient) readLoop() {
	defer func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}()

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				c.onClose(1000, "normal close")
				return
			}
			c.onError(err)
			return
		}
		c.onMessage(data)
	}
}

func (c *KalshiWebSocketClient) onMessage(message []byte) {
	fmt.Println("Received message:", string(message))
}

func (c *KalshiWebSocketClient) onError(err error) {
	fmt.Println("WebSocket error:", err)
}

func (c *KalshiWebSocketClient) onClose(code int, reason string) {
	fmt.Println("WebSocket connection closed with code:", code, "and message:", reason)
}

// ---------- Helpers ----------

// Parse an RSA private key from PEM bytes
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse pem block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an rsa private key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

