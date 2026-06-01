#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# ANSI escape codes for coloring terminal output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Setting up Git hooks for this repository...${NC}"

# 1. Make pre-commit hook executable
chmod +x githooks/pre-commit
echo -e "${GREEN}✓ Made githooks/pre-commit executable.${NC}"

# 2. Configure Git core.hooksPath to point to our custom githooks directory
git config core.hooksPath githooks
echo -e "${GREEN}✓ Configured Git to use local 'githooks' folder.${NC}"

echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}   Git hooks have been successfully configured! ${NC}"
echo -e "${GREEN}===============================================${NC}"
echo "Pre-commit checks (Gitleaks and Semgrep) will now run automatically on git commit."
