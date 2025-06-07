#!/bin/bash

echo "Running Go MCP Library Tests..."
echo "================================"

# Run tests with coverage
go test ./... -cover -v

echo ""
echo "Test Summary:"
echo "============="

# Run tests again with just coverage summary
go test ./... -cover | grep -E "(ok|FAIL|\tcoverage:)"

echo ""
echo "To run specific package tests:"
echo "  go test ./server -v"
echo "  go test ./transport -v" 
echo "  go test ./types -v"
echo ""
echo "To run examples:"
echo "  go run examples/simple/main.go"
echo "  go run examples/typed/main.go"
echo "  go run examples/http/main.go"