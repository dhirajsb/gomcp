#!/bin/bash

# Script to sync Claude's todo list to todos.md
# This script would be called whenever todos are updated

set -e

# Check if todos data is provided via stdin or file
if [ -p /dev/stdin ]; then
    # Read from stdin
    TODOS_JSON=$(cat)
elif [ -f "todo_data.json" ]; then
    # Read from file
    TODOS_JSON=$(cat todo_data.json)
else
    echo "No todo data provided. Use stdin or create todo_data.json"
    exit 1
fi

# Create temporary Go program to sync todos
cat > /tmp/sync_todos.go << 'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Todo struct {
	Content  string `json:"content"`
	Status   string `json:"status"`
	Priority string `json:"priority"`
	ID       string `json:"id"`
}

func main() {
	var todos []Todo
	
	// Read todos from stdin
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&todos); err != nil {
		fmt.Printf("Error parsing todos: %v\n", err)
		os.Exit(1)
	}

	// Group by priority
	priorities := map[string][]Todo{
		"high":   {},
		"medium": {},
		"low":    {},
	}

	for _, todo := range todos {
		priorities[todo.Priority] = append(priorities[todo.Priority], todo)
	}

	// Build markdown
	var md strings.Builder
	md.WriteString("# GoMCP Library Todo List\n\n")

	sections := []struct {
		key   string
		title string
	}{
		{"high", "High Priority"},
		{"medium", "Medium Priority"},
		{"low", "Low Priority"},
	}

	for _, section := range sections {
		sectionTodos := priorities[section.key]
		if len(sectionTodos) == 0 {
			continue
		}

		md.WriteString(fmt.Sprintf("## %s\n\n", section.title))

		sort.Slice(sectionTodos, func(i, j int) bool {
			return sectionTodos[i].ID < sectionTodos[j].ID
		})

		for _, todo := range sectionTodos {
			checkbox := "[ ]"
			if todo.Status == "completed" {
				checkbox = "[x]"
			} else if todo.Status == "in_progress" {
				checkbox = "[⏳]"
			}
			md.WriteString(fmt.Sprintf("- %s %s\n", checkbox, todo.Content))
		}
		md.WriteString("\n")
	}

	// Write to todos.md in current directory
	if err := os.WriteFile("todos.md", []byte(strings.TrimSpace(md.String())), 0644); err != nil {
		fmt.Printf("Error writing todos.md: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully synced todos to todos.md")
}
EOF

# Run the sync
echo "$TODOS_JSON" | go run /tmp/sync_todos.go

# Clean up
rm -f /tmp/sync_todos.go

echo "Todo sync completed"