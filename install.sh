#!/bin/bash

# ==============================================================================
# INSTALADOR ROBUSTO - PYSTALKER v2.0 PRO
# DESENVOLVIDO POR BRUMASEC | BUG BOUNTY & RECON FRAMEWORK
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo -e "${CYAN}"
echo '  ██████╗ ██╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ '
echo '  ██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗'
echo '  ██████╔╝ ╚████╔╝ ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝'
echo '  ██╔═══╝   ╚██╔╝  ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗'
echo '  ██║        ██║   ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║'
echo '  ╚═╝        ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝'
echo -e "${MAGENTA}       ⚡ PyStalker v2.0 Pro Installer • BRUMASEC ⚡${NC}\n"

check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Sucesso!${NC}"
    else
        echo -e "${RED}[X] Atenção: comando retornou código diferente de zero.${NC}"
    fi
}

# 1. Dependências do Sistema
echo -e "${YELLOW}[*] Atualizando repositórios e instalando dependências base...${NC}"
sudo apt-get update -y
sudo apt-get install -y git curl wget unzip python3 python3-pip python3-venv libpcap-dev plocate nmap xclip

# 2. Dependências Python
echo -e "\n${YELLOW}[*] Instalando dependências Python (rich, requests, dnspython, bs4)...${NC}"
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
    check_success
fi

# 3. Configuração do Go
echo -e "\n${YELLOW}[*] Verificando Go (Golang)...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Baixando e instalando Go estável...${NC}"
    wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz -O /tmp/go_setup.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go_setup.tar.gz
    rm /tmp/go_setup.tar.gz
    export PATH=$PATH:/usr/local/go/bin
fi

export GOPATH=$HOME/go
export GOBIN=$HOME/go/bin
export PATH=$PATH:/usr/local/go/bin:$GOBIN

add_path_to_profile() {
    FILE="$1"
    if [ -f "$FILE" ]; then
        if ! grep -q "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" "$FILE"; then
            echo >> "$FILE"
            echo '# Go PATH - PyStalker' >> "$FILE"
            echo 'export GOPATH=$HOME/go' >> "$FILE"
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$FILE"
            echo -e "${GREEN}[+] PATH adicionado a $FILE${NC}"
        fi
    fi
}

add_path_to_profile "$HOME/.bashrc"
add_path_to_profile "$HOME/.zshrc"

install_go_tool() {
    PKG=$1
    NAME=$2
    if ! command -v "$NAME" &> /dev/null && [ ! -f "$GOBIN/$NAME" ]; then
        echo -e "${BLUE} > Instalando $NAME via Go...${NC}"
        go install -v "$PKG"
        if [ -f "$GOBIN/$NAME" ]; then
            sudo cp "$GOBIN/$NAME" /usr/local/bin/ 2>/dev/null
            sudo chmod +x "/usr/local/bin/$NAME" 2>/dev/null
            echo -e "${GREEN}[✓] $NAME instalado com sucesso!${NC}"
        fi
    else
        echo -e "${GREEN}[✓] $NAME já está instalado.${NC}"
    fi
}

# 4. Ferramentas OSINT & Recon
echo -e "\n${YELLOW}[*] Instalando/Verificando ferramentas de Recon...${NC}"

# Subfinder
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"

# Assetfinder
install_go_tool "github.com/tomnomnom/assetfinder@latest" "assetfinder"

# Waybackurls
install_go_tool "github.com/tomnomnom/waybackurls@latest" "waybackurls"

# Httpx Toolkit
if ! command -v httpx-toolkit &> /dev/null && ! command -v httpx &> /dev/null; then
    sudo apt-get install -y httpx-toolkit 2>/dev/null || install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"
fi

# Nuclei
if ! command -v nuclei &> /dev/null; then
    sudo apt-get install -y nuclei 2>/dev/null || install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
fi

# Findomain
if ! command -v findomain &> /dev/null; then
    echo -e "${BLUE} > Baixando binário Findomain...${NC}"
    wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain.zip
    unzip -o /tmp/findomain.zip -d /tmp/
    chmod +x /tmp/findomain
    sudo mv /tmp/findomain /usr/local/bin/findomain
    rm /tmp/findomain.zip
fi

# Permissões executáveis no PyStalker
chmod +x PyStalker.py

# 5. Checklist Final
echo -e "\n${CYAN}================================================================${NC}"
echo -e "${MAGENTA}                    CHECKLIST DE FERRAMENTAS                    ${NC}"
echo -e "${CYAN}================================================================${NC}"

check_tool() {
    TOOL=$1
    if command -v "$TOOL" &> /dev/null; then
        echo -e "${GREEN}[✓] $TOOL ......... INSTALADO ($(which $TOOL))${NC}"
    else
        echo -e "${YELLOW}[!] $TOOL ......... NÃO ENCONTRADO (fallback interno em Python ativo)${NC}"
    fi
}

check_tool "python3"
check_tool "subfinder"
check_tool "assetfinder"
check_tool "findomain"
check_tool "httpx-toolkit"
check_tool "waybackurls"
check_tool "nuclei"
check_tool "nmap"

echo -e "\n${GREEN}[✓] Instalação e configuração concluídas com sucesso!${NC}"
echo -e "${CYAN}[*] Para iniciar, execute:${NC}"
echo -e "    python3 PyStalker.py <alvo.com>"
echo -e "    python3 PyStalker.py --mock\n"
