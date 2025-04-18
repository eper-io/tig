#!/bin/bash

# This document is Licensed under Creative Commons CC0.
# To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
# to this document to the public domain worldwide.
# This document is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with this document.
# If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

# This script will commit the current codebase to a tig server.
# It also returns an example, how to run it as a golang application.
# Usage:
# DATAGET=https://www.botanical23.com DATASET=https://www.botanical23.com ./documentation/commit.sh

tar --exclude .git --exclude-from=.gitignore -c . | curl --data-binary @- -X POST $DATASET >/tmp/code.txt
echo 'cd /go/src'';''curl '$DATAGET$(cat /tmp/code.txt)' | tar -x'';''go run main.go'
