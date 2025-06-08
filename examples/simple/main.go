package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhirajsb/gomcp/pkg/gomcp"
)

func main() {
	server := gomcp.NewServer()

	// Register tools
	server.RegisterTool("add", Add)
	server.RegisterTool("search_files", SearchFiles)

	// Register resources
	server.RegisterResource("file_content", GetFileContent)

	// Register prompts
	server.RegisterPrompt("code_review", CodeReviewPrompt)

	// Start server with stdio transport
	log.Fatal(server.Start(gomcp.Stdio()))
}

// Add adds two numbers
func Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

// SearchFiles searches for files in a directory
func SearchFiles(ctx context.Context, query, directory string, maxFiles int) ([]string, error) {
	if directory == "" {
		directory = "."
	}
	if maxFiles <= 0 {
		maxFiles = 10
	}

	var results []string

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if len(results) >= maxFiles {
			return filepath.SkipDir
		}

		if !info.IsDir() && strings.Contains(strings.ToLower(info.Name()), strings.ToLower(query)) {
			results = append(results, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}

// GetFileContent reads file content
func GetFileContent(ctx context.Context, filepath string) (string, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// CodeReviewPrompt generates a code review prompt
func CodeReviewPrompt(ctx context.Context, language, code string) (string, error) {
	return fmt.Sprintf(`Please review this %s code for:
- Code quality and best practices
- Potential bugs or security issues
- Performance optimizations
- Readability improvements

Code:
%s

Provide specific feedback with examples.`, language, code), nil
}
