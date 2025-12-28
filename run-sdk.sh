#!/bin/bash

# ui
./bin/ui -addr localhost:8020 -traderd-sock /tmp/traderd.sock >ui.log 2>&1 &

# server
./bin/traderd --allowlist-file=./allowlist.txt

