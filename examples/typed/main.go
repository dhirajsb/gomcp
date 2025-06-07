package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhirajsb/gomcp"
)

func main() {
	// Quick API usage
	err := gomcp.Quick().
		Tool("advanced_search", AdvancedSearchFiles).
		Tool("calculate", Calculate).
		Resource("system_info", GetSystemInfo).
		Prompt("documentation", DocumentationPrompt).
		Run()

	log.Fatal(err)
}

// Structured parameter types with validation

type SearchParams struct {
	Query     string   `json:"query" validate:"required,min=1"`
	Directory string   `json:"directory,omitempty" validate:"omitempty,dir"`
	MaxFiles  int      `json:"maxFiles,omitempty" validate:"omitempty,min=1,max=1000"`
	FileTypes []string `json:"fileTypes,omitempty" validate:"dive,oneof=go js ts py java"`
	Recursive bool     `json:"recursive,omitempty"`
}

type SearchResult struct {
	Files     []string `json:"files"`
	Count     int      `json:"count"`
	Truncated bool     `json:"truncated"`
}

func AdvancedSearchFiles(ctx context.Context, params SearchParams) (SearchResult, error) {
	directory := params.Directory
	if directory == "" {
		directory = "."
	}

	maxFiles := params.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 100
	}

	var results []string
	totalCount := 0

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if !params.Recursive && filepath.Dir(path) != directory {
			if info.IsDir() && path != directory {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Check file type filter
		if len(params.FileTypes) > 0 {
			ext := strings.TrimPrefix(filepath.Ext(info.Name()), ".")
			found := false
			for _, allowedExt := range params.FileTypes {
				if ext == allowedExt {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}

		// Check query match
		if strings.Contains(strings.ToLower(info.Name()), strings.ToLower(params.Query)) {
			totalCount++
			if len(results) < maxFiles {
				results = append(results, path)
			}
		}

		return nil
	}

	err := filepath.Walk(directory, walkFunc)
	if err != nil {
		return SearchResult{}, err
	}

	return SearchResult{
		Files:     results,
		Count:     totalCount,
		Truncated: totalCount > len(results),
	}, nil
}

type CalculationParams struct {
	Operation string  `json:"operation" validate:"required,oneof=add subtract multiply divide"`
	A         float64 `json:"a" validate:"required"`
	B         float64 `json:"b" validate:"required"`
}

type CalculationResult struct {
	Result  float64 `json:"result"`
	Formula string  `json:"formula"`
}

func Calculate(ctx context.Context, params CalculationParams) (CalculationResult, error) {
	var result float64
	var formula string

	switch params.Operation {
	case "add":
		result = params.A + params.B
		formula = fmt.Sprintf("%.2f + %.2f = %.2f", params.A, params.B, result)
	case "subtract":
		result = params.A - params.B
		formula = fmt.Sprintf("%.2f - %.2f = %.2f", params.A, params.B, result)
	case "multiply":
		result = params.A * params.B
		formula = fmt.Sprintf("%.2f × %.2f = %.2f", params.A, params.B, result)
	case "divide":
		if params.B == 0 {
			return CalculationResult{}, fmt.Errorf("division by zero")
		}
		result = params.A / params.B
		formula = fmt.Sprintf("%.2f ÷ %.2f = %.2f", params.A, params.B, result)
	default:
		return CalculationResult{}, fmt.Errorf("unknown operation: %s", params.Operation)
	}

	return CalculationResult{
		Result:  result,
		Formula: formula,
	}, nil
}

type SystemInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	WorkingDir   string `json:"workingDir"`
	GoVersion    string `json:"goVersion"`
}

func GetSystemInfo(ctx context.Context) (SystemInfo, error) {
	wd, _ := os.Getwd()

	return SystemInfo{
		OS:           "linux", // Simplified
		Architecture: "amd64", // Simplified
		WorkingDir:   wd,
		GoVersion:    "1.21+", // Simplified
	}, nil
}

type DocumentationParams struct {
	Language        string `json:"language" validate:"required,oneof=go python javascript typescript java"`
	Code            string `json:"code" validate:"required,min=10"`
	Style           string `json:"style,omitempty" validate:"omitempty,oneof=javadoc sphinx godoc jsdoc"`
	IncludeExamples bool   `json:"includeExamples,omitempty"`
}

func DocumentationPrompt(ctx context.Context, params DocumentationParams) (string, error) {
	exampleText := ""
	if params.IncludeExamples {
		exampleText = "\n- Provide clear usage examples"
	}

	styleInstruction := ""
	switch params.Style {
	case "javadoc":
		styleInstruction = "Use Javadoc format with @param, @return, etc."
	case "sphinx":
		styleInstruction = "Use Sphinx/reStructuredText format."
	case "godoc":
		styleInstruction = "Use Go documentation conventions."
	case "jsdoc":
		styleInstruction = "Use JSDoc format with @param, @returns, etc."
	default:
		styleInstruction = fmt.Sprintf("Use the standard documentation format for %s.", params.Language)
	}

	return fmt.Sprintf(`Please create comprehensive documentation for this %s code:

%s

Requirements:
- Write clear, concise descriptions
- Document all parameters and return values
- Follow %s documentation standards%s
- Be specific about types and constraints
- Include any important notes about usage or behavior

%s`,
		params.Language, params.Code, params.Language, exampleText, styleInstruction), nil
}
