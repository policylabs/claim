# SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
# SPDX-License-Identifier: Apache-2.0

.PHONY: build test lint

build:
	go build -o bin/claim ./cmd/claim

test:
	go test -race ./...

lint:
	golangci-lint run ./...
