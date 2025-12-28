package main

import (
//  "fmt"
  "log"
  "strings"
  "flag"
  "os"
  "net"
  "net/http"
  "time"
  "encoding/base64"
  "crypto/ed25519"
  "crypto/rand"
  "context"
  "syscall"
  "errors"
  "os/signal"
  bbolt "go.etcd.io/bbolt"
  traderd "sdk-magma/traderd_server"
  backup "sdk-magma/traderd_backup"
)

func main() {

  traderd.PrintStartupBanner("Magma TraderD", "Local Trading Daemon (auditable + signed IPC)", "v0.1.0")

  if err := backup.RotateAndBackupTraderDB(); err != nil {
    log.Fatal(err)
  }

  for {
    var err error
    err = traderd.PromptAndStorePasswordHash2Pwd("./traderd.db")
    if err == nil { break; }
  }

  // Generate signing key (demo: ephemeral each run).
  // For production, load from a file so the pubkey is stable across restarts.
  pub, priv, err := ed25519.GenerateKey(rand.Reader)
  if err != nil { log.Fatal(err) }
  traderd.SignPub, traderd.SignPriv = pub, priv

  sock := flag.String("sock", "/tmp/traderd.sock", "unix socket path")
  dbPath := flag.String("db", "./traderd.db", "boltdb path")
  allowlistFile := flag.String("allowlist-file", "", "path to allowlist file (one domain per line, supports # comments)")
  flag.Parse()

  if strings.TrimSpace(*allowlistFile) == "" {
    log.Fatal("missing required flag: --allowlist-file=/etc/traderd/allowlist.txt")
  }

  allowed, err := traderd.LoadAllowlistFile(*allowlistFile)
  if err != nil {
    log.Fatal(err)
  }
  if len(allowed) == 0 {
    log.Fatal("allowlist is empty (refusing to start): ", *allowlistFile)
  }

  // Open BoltDB once and reuse the handle.
  db, err := bbolt.Open(*dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()

  // Use this for ALL outbound calls to exchanges.
  outbound := traderd.NewAllowlistedHTTPClient(allowed)
  _ = outbound // keep it for future exchange calls

  _ = os.Remove(*sock)

  l, err := net.Listen("unix", *sock)
  if err != nil {
    log.Fatal(err)
  }
  defer l.Close()

  // safer than 0666
  _ = os.Chmod(*sock, 0660)

  mux := http.NewServeMux()

  mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
      http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
      return
    }
    traderd.WriteSignedJSON(w, http.StatusOK, traderd.RequestIDFromContext(r.Context()), map[string]string{
      "alg": "ed25519",
      "pub": base64.StdEncoding.EncodeToString(traderd.SignPub),
    })
  })

  mux.HandleFunc("/hashpwd", traderd.HashpwdHandler)

  mux.HandleFunc("/list-record-ids", traderd.ListRecordIDsHandler(db))
  mux.HandleFunc("/write-record", traderd.StoreWriteHandler(db))
  mux.HandleFunc("/read-record", traderd.StoreReadHandler(db))

  mux.HandleFunc("/health", traderd.HealthHandler)
  mux.HandleFunc("/place", traderd.PlaceHandler)

  srv := &http.Server{
    Handler:           traderd.LoggingMiddleware(mux),
    ReadHeaderTimeout: 2 * time.Second,
    ReadTimeout:       traderd.ReadTimeout,
    WriteTimeout:      traderd.WriteTimeout,
    IdleTimeout:       traderd.IdleTimeout,
  }

  log.Println("daemon listening on unix socket:", *sock)
  log.Println("outbound allowlist loaded from:", *allowlistFile)
  log.Println("outbound allowlist:", strings.Join(allowed, ","))

  ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
  defer stop()
  go func() {
     <-ctx.Done()
    log.Println("shutdown requested")
    shCtx, cancel := context.WithTimeout(context.Background(), traderd.ShutdownTimeout)
    defer cancel()
    _ = srv.Shutdown(shCtx)
  }()

  if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
    log.Fatal(err)
  }

  _ = os.Remove(*sock)
  log.Println("daemon stopped")

}
