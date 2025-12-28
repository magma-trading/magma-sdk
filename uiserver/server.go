package uiserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

//go:embed api-settings.html
var webFS embed.FS

type ExchangeConfig struct {
	APIKey      string `json:"apiKey"`
	APISecret   string `json:"apiSecret"`
	Passphrase  string `json:"passphrase"`
	Label       string `json:"label"`
	Testnet     bool   `json:"testnet"`
	UpdatedAtUT string `json:"updatedAtUtc"`
}

type WSMsg struct {
	Type     string                    `json:"type"`
	Exchange string                    `json:"exchange,omitempty"`
	Config   *ExchangeConfig           `json:"config,omitempty"`
	Data     map[string]ExchangeConfig `json:"data,omitempty"`
	Error    string                    `json:"error,omitempty"`
}

// ---- WS tracking for graceful shutdown ----
var (
	wsMu    sync.Mutex
	wsConns = map[*websocket.Conn]struct{}{}
	wsWG    sync.WaitGroup
)

func trackConn(c *websocket.Conn) {
	wsMu.Lock()
	wsConns[c] = struct{}{}
	wsMu.Unlock()
}
func untrackConn(c *websocket.Conn) {
	wsMu.Lock()
	delete(wsConns, c)
	wsMu.Unlock()
}
func closeAllWebSockets() {
	wsMu.Lock()
	defer wsMu.Unlock()
	for c := range wsConns {
		_ = c.Close()
	}
}

// ---- IPC quit listener (best-effort; no fatal inside a package) ----
func exitPoint(quitMain chan<- string) {
	socketPath := filepath.Join(os.TempDir(), "api-exchanges-ipc.sock")

	_ = os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Printf("IPC listen unix failed (ignored): %v", err)
		return
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(socketPath)
	}()

	log.Printf("IPC listening on %s", socketPath)

	quit := make(chan struct{}, 1)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("signal received, exiting...")
		select {
		case quit <- struct{}{}:
		default:
		}
		_ = l.Close()
		select {
		case quitMain <- "QUIT":
		default:
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-quit:
				log.Println("IPC shutdown complete")
				return
			default:
				log.Printf("IPC accept error: %v", err)
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()

			sc := bufio.NewScanner(c)
			for sc.Scan() {
				msg := strings.TrimSpace(sc.Text())
				if msg == "" {
					continue
				}
				log.Printf("IPC message: %q", msg)

				if strings.EqualFold(msg, "QUIT") {
					select {
					case quit <- struct{}{}:
					default:
					}
					_ = l.Close()
					fmt.Fprintln(c, "OK quitting")

					select {
					case quitMain <- "QUIT":
					default:
					}
					return
				}
				fmt.Fprintln(c, "OK")
			}
		}(conn)
	}
}

// Run starts the UI server and blocks until shutdown.
func Run(addr string, traderdSock string) error {
  // Connect to traderd once (pubkey + signed hashpwd), keep in memory

/*
  td, err := NewTraderDClient(traderdSock)
  if err != nil {
    return fmt.Errorf("connect traderd: %w", err)
  }
  log.Printf("connected traderd: pubkey=%d bytes; hashpwd loaded in memory", len(td.pub))
  log.Printf("traderd-sock: %s", traderdSock)
*/


  var td *TraderDClient

  for {
    var err error
    td, err = NewTraderDClient(traderdSock)
    if err == nil {
      break
    }
    log.Printf("connect traderd failed (%s): %v; retrying in 3s...", traderdSock, err)
    time.Sleep(3 * time.Second)
  }
  log.Printf("connected traderd: pubkey=%d bytes; hashpwd loaded in memory", len(td.pub))
  log.Printf("traderd-sock: %s", traderdSock)

	quit := make(chan string, 1)
	go exitPoint(quit)

	mux := http.NewServeMux()

	// Serve the embedded HTML
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("api-settings.html")
		if err != nil {
			http.Error(w, "missing api-settings.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	// WebSocket endpoint (wrapped so we can track conns)
	wsServer := websocket.Server{
		Handshake: func(cfg *websocket.Config, r *http.Request) error {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return nil
			}
			u, err := url.Parse(origin)
			if err != nil {
				return err
			}
			reqHost := r.Host
			if !strings.EqualFold(u.Host, reqHost) && !isLocalHost(u.Host) {
				// optional tighten here:
				// return fmt.Errorf("origin not allowed: %s", u.Host)
			}
			cfg.Origin = u
			return nil
		},
		Handler: websocket.Handler(func(conn *websocket.Conn) {
			wsWG.Add(1)
			trackConn(conn)
			defer func() {
				untrackConn(conn)
				_ = conn.Close()
				wsWG.Done()
			}()
			handleWS(conn, td)
		}),
	}
	mux.Handle("/ws", wsServer)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("open: http://%s/", addr)
		log.Printf("ws:   ws://%s/ws", addr)
		serverErr <- srv.ListenAndServe()
	}()

	var once sync.Once
	shutdown := func(reason string) {
		once.Do(func() {
			log.Printf("Shutting down (%s)...", reason)

			closeAllWebSockets()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)

			wsWG.Wait()
			log.Printf("bye")
		})
	}

	select {
	case msg := <-quit:
		if strings.EqualFold(msg, "QUIT") {
			shutdown("IPC QUIT")
		} else {
			shutdown("IPC " + msg)
		}
		return nil

	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			shutdown("server error")
			return err
		}
		shutdown("server closed")
		return nil
	}
}

func isLocalHost(host string) bool {
	h := host
	if strings.Contains(host, ":") {
		h, _, _ = strings.Cut(host, ":")
	}
	switch strings.ToLower(h) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

func handleWS(conn *websocket.Conn, td *TraderDClient) {
	for {
		var raw string
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return
		}

		var msg WSMsg
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			_ = sendErr(conn, "invalid json")
			continue
		}

		switch msg.Type {

		case "list":
			data, err := td.ListConfigsAsLegacyMap()
			if err != nil {
				_ = sendErr(conn, err.Error())
				continue
			}
			_ = sendJSON(conn, WSMsg{Type: "list", Data: data})

		case "save":
			if strings.TrimSpace(msg.Exchange) == "" || msg.Config == nil {
				_ = sendErr(conn, "missing exchange or config")
				continue
			}
			ex := strings.TrimSpace(msg.Exchange)

			cfg := *msg.Config
			cfg.UpdatedAtUT = time.Now().UTC().Format(time.RFC3339)

			if _, err := td.UpsertExchangeConfig(ex, cfg); err != nil {
				_ = sendErr(conn, err.Error())
				continue
			}

			_ = sendJSON(conn, WSMsg{Type: "saved", Exchange: ex, Config: &cfg})

		default:
			_ = sendErr(conn, "unknown message type")
		}
	}
}

func sendErr(conn *websocket.Conn, errMsg string) error {
	return sendJSON(conn, WSMsg{Type: "error", Error: errMsg})
}

func sendJSON(conn *websocket.Conn, msg WSMsg) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return websocket.Message.Send(conn, string(b))
}

/* =========================================================
   TraderDClient (signed IPC over unix socket)
   ========================================================= */

type TraderDClient struct {
	http    *http.Client
	pub     ed25519.PublicKey
	hashpwd string

	mu           sync.RWMutex
	exchangeToID map[string]string // exchange -> apiId(field0)
}

type TD_PubKeyResp struct {
	Alg string `json:"alg"`
	Pub string `json:"pub"`
}

type TD_HashpwdResp struct {
	Hashpwd string `json:"hashpwd"`
}

type TD_ListIDsRes struct {
	OK  bool     `json:"ok"`
	Msg string   `json:"msg"`
	ID  string   `json:"id,omitempty"`
	IDs []string `json:"ids,omitempty"`
}

type TD_ReadRecordReq struct {
	Hashpwd string `json:"hashpwd"`
	Field0  string `json:"field0"`
}

type TD_WriteRecordReq struct {
	Hashpwd string    `json:"hashpwd"`
	Record  TD_Record `json:"record"`
}

// traderd record model (field0..field8)
type TD_Record struct {
	Field0 string    `json:"field0"` // apiId
	Field1 string    `json:"field1"` // exchange
	Field2 time.Time `json:"field2"` // updated
	Field3 string    `json:"field3"` // apiKey
	Field4 string    `json:"field4"` // apiSecret
	Field5 string    `json:"field5"` // passphrase
	Field6 string    `json:"field6"` // label
	Field7 bool      `json:"field7"` // testnet
	Field8 bool      `json:"field8"` // apiEnabled
}

func NewTraderDClient(sock string) (*TraderDClient, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	pub, err := tdFetchPubKey(hc)
	if err != nil {
		return nil, err
	}
	hashpwd, err := tdFetchHashpwd(hc, pub)
	if err != nil {
		return nil, err
	}

	td := &TraderDClient{
		http:         hc,
		pub:          pub,
		hashpwd:      hashpwd,
		exchangeToID: map[string]string{},
	}
	return td, nil
}

func (t *TraderDClient) ListConfigsAsLegacyMap() (map[string]ExchangeConfig, error) {
	ids, err := t.listIDs()
	if err != nil {
		return nil, err
	}

	out := make(map[string]ExchangeConfig)
	cache := make(map[string]string)

	for _, id := range ids {
		rec, err := t.readRecord(id)
		if err != nil {
			return nil, fmt.Errorf("read record id=%s: %w", id, err)
		}
		ex := strings.TrimSpace(rec.Field1)
		if ex == "" {
			continue
		}

		cfg := ExchangeConfig{
			APIKey:      rec.Field3,
			APISecret:   rec.Field4,
			Passphrase:  rec.Field5,
			Label:       rec.Field6,
			Testnet:     rec.Field7,
			UpdatedAtUT: rec.Field2.UTC().Format(time.RFC3339),
		}

		prev, ok := out[ex]
		if !ok {
			out[ex] = cfg
			cache[ex] = rec.Field0
			continue
		}
		prevT, _ := time.Parse(time.RFC3339, prev.UpdatedAtUT)
		if rec.Field2.After(prevT) {
			out[ex] = cfg
			cache[ex] = rec.Field0
		}
	}

	t.mu.Lock()
	t.exchangeToID = cache
	t.mu.Unlock()

	return out, nil
}

func (t *TraderDClient) UpsertExchangeConfig(exchange string, cfg ExchangeConfig) (string, error) {
	ex := strings.TrimSpace(exchange)
	if ex == "" {
		return "", fmt.Errorf("exchange empty")
	}

	t.mu.RLock()
	id := t.exchangeToID[ex]
	t.mu.RUnlock()

	if id == "" {
		_, _ = t.ListConfigsAsLegacyMap()
		t.mu.RLock()
		id = t.exchangeToID[ex]
		t.mu.RUnlock()
	}
	if id == "" {
		id = randomIDHex16()
	}

	rec := TD_Record{
		Field0: id,
		Field1: ex,
		Field2: time.Now().UTC(),
		Field3: cfg.APIKey,
		Field4: cfg.APISecret,
		Field5: cfg.Passphrase,
		Field6: cfg.Label,
		Field7: cfg.Testnet,
		Field8: true, // HTML doesn't expose apiEnabled toggle yet
	}

	if err := t.writeRecord(rec); err != nil {
		return "", err
	}

	t.mu.Lock()
	t.exchangeToID[ex] = id
	t.mu.Unlock()

	return id, nil
}

/* ---------- traderd calls ---------- */

func (t *TraderDClient) listIDs() ([]string, error) {
	req, _ := http.NewRequest("GET", "http://unix/list-record-ids", nil)
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if err := tdVerify(t.pub, resp, raw); err != nil {
		return nil, err
	}

	var lr TD_ListIDsRes
	if err := json.Unmarshal(raw, &lr); err != nil {
		return nil, err
	}
	if !lr.OK {
		return nil, fmt.Errorf("list-record-ids failed: %s", lr.Msg)
	}
	return lr.IDs, nil
}

func (t *TraderDClient) readRecord(id string) (TD_Record, error) {
	body, _ := json.Marshal(TD_ReadRecordReq{Hashpwd: t.hashpwd, Field0: id})
	req, _ := http.NewRequest("POST", "http://unix/read-record", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return TD_Record{}, err
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return TD_Record{}, err
	}
	if err := tdVerify(t.pub, resp, raw); err != nil {
		return TD_Record{}, err
	}

	var wrap struct {
		OK     bool       `json:"ok"`
		Msg    string     `json:"msg"`
		Record *TD_Record `json:"record"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return TD_Record{}, err
	}
	if !wrap.OK || wrap.Record == nil {
		return TD_Record{}, fmt.Errorf("read failed: %s", wrap.Msg)
	}
	return *wrap.Record, nil
}

func (t *TraderDClient) writeRecord(rec TD_Record) error {
	body, _ := json.Marshal(TD_WriteRecordReq{Hashpwd: t.hashpwd, Record: rec})
	req, _ := http.NewRequest("POST", "http://unix/write-record", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if err := tdVerify(t.pub, resp, raw); err != nil {
		return err
	}

	var wrap struct {
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return err
	}
	if !wrap.OK {
		return fmt.Errorf("write failed: %s", wrap.Msg)
	}
	return nil
}

/* ---------- fetch pubkey/hashpwd + signature verify ---------- */

func tdFetchPubKey(c *http.Client) (ed25519.PublicKey, error) {
	req, _ := http.NewRequest("GET", "http://unix/pubkey", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var pk TD_PubKeyResp
	if err := json.Unmarshal(raw, &pk); err != nil {
		return nil, err
	}
	if pk.Alg != "ed25519" {
		return nil, fmt.Errorf("unexpected alg: %q", pk.Alg)
	}
	b, err := base64.StdEncoding.DecodeString(pk.Pub)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad pubkey size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func tdFetchHashpwd(c *http.Client, pub ed25519.PublicKey) (string, error) {
	req, _ := http.NewRequest("GET", "http://unix/hashpwd", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if err := tdVerify(pub, resp, raw); err != nil {
		return "", err
	}

	var out TD_HashpwdResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Hashpwd == "" {
		return "", fmt.Errorf("server returned empty hashpwd")
	}
	return out.Hashpwd, nil
}

func tdVerify(pub ed25519.PublicKey, resp *http.Response, raw []byte) error {
	reqID := resp.Header.Get("X-Req-Id")
	sigB64 := resp.Header.Get("X-Signature")
	if reqID == "" || sigB64 == "" {
		return fmt.Errorf("missing signature headers (X-Req-Id or X-Signature), http=%s", resp.Status)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("bad signature base64: %w", err)
	}
	msg := append([]byte(reqID+"\n"), raw...)
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("invalid server signature, http=%s", resp.Status)
	}
	return nil
}

func randomIDHex16() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
