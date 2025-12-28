package main

import (
  "flag"
  "log"
  "sdk-magma/uiserver"
)

func main() {

  addr := flag.String("addr", "localhost:8020", "listen address")
  traderdSock := flag.String("traderd-sock", "/tmp/traderd.sock", "traderd unix socket path")
  flag.Parse()

  if err := uiserver.Run(*addr, *traderdSock); err != nil {
    log.Fatal(err)
  }

}
