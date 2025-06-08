package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Todo represents a single todo item
type Todo struct {
	Content  string `json:"content"`
	Status   string `json:"status"`
	Priority string `json:"priority"`
	ID       string `json:"id"`
}

// syncTodosToMarkdown reads todos from Claude's todo system and updates todos.md
func syncTodosToMarkdown(todos []Todo, filename string) error {
	// Group todos by priority
	priorities := map[string][]Todo{
		"high":   {},
		"medium": {},
		"low":    {},
	}

	for _, todo := range todos {
		priorities[todo.Priority] = append(priorities[todo.Priority], todo)
	}

	// Build markdown content
	var md strings.Builder
	md.WriteString("# GoMCP Library Todo List\n\n")

	// Write sections in order
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

		// Sort todos by ID for consistent ordering
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

	// Write to file
	return os.WriteFile(filename, []byte(strings.TrimSpace(md.String())), 0644)
}

// Usage example (this would be called by Claude)
func main() {
	// Example todos (this would come from Claude's TodoRead)
	todos := []Todo{
		{Content: "Add automatic JSON schema generation", Status: "pending", Priority: "high", ID: "mcp-schema-generation"},
		{Content: "Create CLI tool for scaffolding", Status: "completed", Priority: "high", ID: "cli-scaffolding"},
		{Content: "Add hot reload development mode", Status: "in_progress", Priority: "high", ID: "hot-reload"},
	}

	if err := syncTodosToMarkdown(todos, "todos.md"); err != nil {
		fmt.Printf("Error syncing todos: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully synced todos to todos.md")
}