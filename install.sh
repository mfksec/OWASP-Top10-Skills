#!/bin/bash
# OWASP Security Skill Installation Script
# Installs the comprehensive OWASP security skill for Claude, Copilot, or other LLM assistants

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    SKILLS_BASE="${HOME}/.config"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    SKILLS_BASE="${HOME}"
else
    SKILLS_BASE="${HOME}"
fi

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}OWASP Security Skill Installer${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to install skill
install_skill() {
    local assistant=$1
    local skill_path=$2
    local install_dir="${SKILLS_BASE}/${skill_path}"
    
    echo -e "${YELLOW}Installing for:${NC} $assistant"
    echo -e "Target path: ${install_dir}"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$install_dir")"
    
    # Verify current directory is OWASP-Security-Skills repo
    if [ ! -f "owasp-comprehensive-security-skills.md" ]; then
        echo -e "${RED}✗ Error: Please run this script from the OWASP-Security-Skills directory${NC}"
        return 1
    fi
    
    # Remove existing installation if present
    if [ -L "$install_dir" ]; then
        echo "Removing existing symlink..."
        rm "$install_dir"
    elif [ -d "$install_dir" ]; then
        echo "Backing up existing installation..."
        mv "$install_dir" "${install_dir}.backup.$(date +%s)"
    fi
    
    # Create symlink
    ln -s "$(pwd)" "$install_dir"
    
    if [ -L "$install_dir" ]; then
        echo -e "${GREEN}✓ Successfully installed to: ${install_dir}${NC}"
        return 0
    else
        echo -e "${RED}✗ Installation failed${NC}"
        return 1
    fi
}

# Function to verify installation
verify_installation() {
    local install_dir=$1
    
    echo -e "\n${YELLOW}Verifying installation...${NC}"
    
    local required_files=(
        "owasp-comprehensive-security-skills.md"
        "owasp-css.instructions.md"
        "README.md"
        "skill.json"
    )
    
    local all_present=true
    for file in "${required_files[@]}"; do
        if [ -f "${install_dir}/${file}" ]; then
            echo -e "  ${GREEN}✓${NC} $file"
        else
            echo -e "  ${RED}✗${NC} $file (missing)"
            all_present=false
        fi
    done
    
    # Check examples directory
    local example_count=$(find "${install_dir}/examples" -type f | wc -l)
    if [ "$example_count" -ge 9 ]; then
        echo -e "  ${GREEN}✓${NC} examples/ ($example_count files)"
    else
        echo -e "  ${RED}✗${NC} examples/ (expected 9, found $example_count)"
        all_present=false
    fi
    
    if [ "$all_present" = true ]; then
        echo -e "${GREEN}✓ All files verified${NC}"
        return 0
    else
        echo -e "${RED}✗ Some files are missing${NC}"
        return 1
    fi
}

# Main menu
echo "Select installation target:"
echo "  1) Claude Desktop (.claude/skills)"
echo "  2) GitHub Copilot (.copilot/skills)"
echo "  3) Custom path"
echo "  4) Test only (no installation)"
echo "  5) Exit"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        install_skill "Claude Desktop" ".claude/skills/owasp-security"
        if [ $? -eq 0 ]; then
            verify_installation "${SKILLS_BASE}/.claude/skills/owasp-security"
            echo -e "\n${GREEN}Next steps:${NC}"
            echo "  1. Restart Claude Desktop"
            echo "  2. Ask: 'Review this code for OWASP vulnerabilities'"
            echo "  3. Paste any example from examples/ folder"
        fi
        ;;
    2)
        install_skill "GitHub Copilot" ".copilot/skills/owasp-security"
        if [ $? -eq 0 ]; then
            verify_installation "${SKILLS_BASE}/.copilot/skills/owasp-security"
            echo -e "\n${GREEN}Next steps:${NC}"
            echo "  1. Restart GitHub Copilot"
            echo "  2. Ask: 'Review this code for OWASP vulnerabilities'"
        fi
        ;;
    3)
        read -p "Enter custom installation path: " custom_path
        install_skill "Custom" "$custom_path"
        if [ $? -eq 0 ]; then
            verify_installation "${SKILLS_BASE}/${custom_path}"
        fi
        ;;
    4)
        echo -e "\n${YELLOW}Running verification only...${NC}"
        echo "Current directory: $(pwd)"
        verify_installation "."
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}Installation complete!${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "For more information, see README.md"
echo "Join discussions: https://github.com/mfkocalar/OWASP-Security-Skills"
