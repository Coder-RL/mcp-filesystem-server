package handler

import (
	"context"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

// isPathInAllowedDirs checks if a path is within any of the allowed directories
func (fs *FilesystemHandler) isPathInAllowedDirs(path string) bool {
	// Ensure path is absolute and clean
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Add trailing separator to ensure we're checking a directory or a file within a directory
	// and not a prefix match (e.g., /tmp/foo should not match /tmp/foobar)
	if !strings.HasSuffix(absPath, string(filepath.Separator)) {
		// If it's a file, we need to check its directory
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
			absPath = filepath.Dir(absPath) + string(filepath.Separator)
		} else {
			absPath = absPath + string(filepath.Separator)
		}
	}

	// Check if the path is within any of the allowed directories
	for _, dir := range fs.allowedDirs {
		if strings.HasPrefix(absPath, dir) {
			return true
		}
	}
	return false
}

// validatePathSecurity performs security validation on raw user input before path resolution
func (fs *FilesystemHandler) validatePathSecurity(requestedPath string) error {
	// Block null bytes (can bypass security checks in some filesystems)
	if strings.Contains(requestedPath, "\x00") {
		return fmt.Errorf("invalid path: contains null byte")
	}

	// Block obvious traversal attempts
	if strings.Contains(requestedPath, "..") {
		return fmt.Errorf("access denied - path traversal attempt detected")
	}

	// Block absolute paths that don't start with allowed prefixes
	if filepath.IsAbs(requestedPath) {
		allowed := false
		for _, allowedDir := range fs.allowedDirs {
			cleanAllowed := strings.TrimSuffix(allowedDir, string(filepath.Separator))
			if strings.HasPrefix(requestedPath, cleanAllowed) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access denied - absolute path outside allowed directories")
		}
	}

	// Block suspicious patterns
	suspiciousPatterns := []string{
		"/../",
		"/./",
		"\\..\\",
		"\\",
		"//",
		"\\/",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(requestedPath, pattern) {
			return fmt.Errorf("access denied - suspicious path pattern detected: %s", pattern)
		}
	}

	// Limit path length to prevent buffer overflow attacks
	if len(requestedPath) > 4096 {
		return fmt.Errorf("access denied - path too long (max 4096 characters)")
	}

	return nil
}

func (fs *FilesystemHandler) validatePath(requestedPath string) (string, error) {
	// Security: Validate path BEFORE resolution to prevent traversal attacks
	if err := fs.validatePathSecurity(requestedPath); err != nil {
		return "", err
	}

	// Convert to absolute path after security validation
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Double-check after resolution
	if !fs.isPathInAllowedDirs(abs) {
		return "", fmt.Errorf(
			"access denied - path outside allowed directories: %s",
			abs,
		)
	}

	// Handle symlinks
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// For new files, check parent directory
		parent := filepath.Dir(abs)
		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", fmt.Errorf("parent directory does not exist: %s", parent)
		}

		if !fs.isPathInAllowedDirs(realParent) {
			return "", fmt.Errorf(
				"access denied - parent directory outside allowed directories",
			)
		}
		return abs, nil
	}

	// Check if the real path (after resolving symlinks) is still within allowed directories
	if !fs.isPathInAllowedDirs(realPath) {
		return "", fmt.Errorf(
			"access denied - symlink target outside allowed directories",
		)
	}

	return realPath, nil
}

// detectMimeType tries to determine the MIME type of a file
func detectMimeType(path string) string {
	// Use mimetype library for more accurate detection
	mtype, err := mimetype.DetectFile(path)
	if err != nil {
		// Fallback to extension-based detection if file can't be read
		ext := filepath.Ext(path)
		if ext != "" {
			mimeType := mime.TypeByExtension(ext)
			if mimeType != "" {
				return mimeType
			}
		}
		return "application/octet-stream" // Default
	}

	return mtype.String()
}

// isTextFile determines if a file is likely a text file based on MIME type
func isTextFile(mimeType string) bool {
	// Check for common text MIME types
	if strings.HasPrefix(mimeType, "text/") {
		return true
	}

	// Common application types that are text-based
	textApplicationTypes := []string{
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-javascript",
		"application/typescript",
		"application/x-typescript",
		"application/x-yaml",
		"application/yaml",
		"application/toml",
		"application/x-sh",
		"application/x-shellscript",
	}

	if slices.Contains(textApplicationTypes, mimeType) {
		return true
	}

	// Check for +format types
	if strings.Contains(mimeType, "+xml") ||
		strings.Contains(mimeType, "+json") ||
		strings.Contains(mimeType, "+yaml") {
		return true
	}

	// Common code file types that might be misidentified
	if strings.HasPrefix(mimeType, "text/x-") {
		return true
	}

	if strings.HasPrefix(mimeType, "application/x-") &&
		(strings.Contains(mimeType, "script") ||
			strings.Contains(mimeType, "source") ||
			strings.Contains(mimeType, "code")) {
		return true
	}

	return false
}

// isImageFile determines if a file is an image based on MIME type
func isImageFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "image/") ||
		(mimeType == "application/xml" && strings.HasSuffix(strings.ToLower(mimeType), ".svg"))
}

// validateRegexSecurity validates regex patterns to prevent ReDoS attacks
func (fs *FilesystemHandler) validateRegexSecurity(pattern string) error {
	// Check pattern length
	if len(pattern) > MAX_REGEX_LENGTH {
		return fmt.Errorf("regex pattern too long (max %d characters)", MAX_REGEX_LENGTH)
	}

	// Block dangerous patterns that can cause exponential backtracking
	dangerousPatterns := []string{
		"(a+)+",          // Nested quantifiers
		"(a*)*",          // Nested quantifiers
		"(a+)*",          // Nested quantifiers
		"(.*)*",          // Nested quantifiers
		"(.+)+",          // Nested quantifiers
		"(a|a)*",         // Alternation with overlap
		"([a-z]+)+",      // Character class with nested quantifiers
		"(\\w+)+",        // Word boundary with nested quantifiers
	}

	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return fmt.Errorf("potentially dangerous regex pattern detected")
		}
	}

	// Count nested quantifiers and alternations
	quantifierCount := strings.Count(pattern, "+") + strings.Count(pattern, "*") + strings.Count(pattern, "?")
	if quantifierCount > 10 {
		return fmt.Errorf("too many quantifiers in regex pattern (max 10)")
	}

	alternationCount := strings.Count(pattern, "|")
	if alternationCount > 20 {
		return fmt.Errorf("too many alternations in regex pattern (max 20)")
	}

	return nil
}

// safeRegexReplaceAll executes ReplaceAllString with timeout protection
func (fs *FilesystemHandler) safeRegexReplaceAll(re *regexp.Regexp, content, replacement string) (string, int, error) {
	type result struct {
		content string
		count   int
		err     error
	}

	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), REGEX_TIMEOUT_SECONDS*time.Second)
	defer cancel()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{"", 0, fmt.Errorf("regex operation panic: %v", r)}
			}
		}()

		replaced := re.ReplaceAllString(content, replacement)
		count := len(re.FindAllString(content, -1))
		ch <- result{replaced, count, nil}
	}()

	select {
	case res := <-ch:
		return res.content, res.count, res.err
	case <-ctx.Done():
		return "", 0, fmt.Errorf("regex operation timed out after %d seconds", REGEX_TIMEOUT_SECONDS)
	}
}

// safeRegexReplaceFirst executes first match replacement with timeout protection
func (fs *FilesystemHandler) safeRegexReplaceFirst(re *regexp.Regexp, content, replacement string) (string, int, error) {
	type result struct {
		content string
		count   int
		err     error
	}

	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), REGEX_TIMEOUT_SECONDS*time.Second)
	defer cancel()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{"", 0, fmt.Errorf("regex operation panic: %v", r)}
			}
		}()

		matched := re.FindStringIndex(content)
		if matched != nil {
			replaced := content[:matched[0]] + replacement + content[matched[1]:]
			ch <- result{replaced, 1, nil}
		} else {
			ch <- result{content, 0, nil}
		}
	}()

	select {
	case res := <-ch:
		return res.content, res.count, res.err
	case <-ctx.Done():
		return "", 0, fmt.Errorf("regex operation timed out after %d seconds", REGEX_TIMEOUT_SECONDS)
	}
}
