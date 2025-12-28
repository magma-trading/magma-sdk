#!/bin/bash

# ui
go run ./cmd/ui -addr localhost:8020 -traderd-sock /tmp/traderd.sock >ui.log 2>&1 &

# server
go run ./cmd/traderd --allowlist-file=./allowlist.txt

