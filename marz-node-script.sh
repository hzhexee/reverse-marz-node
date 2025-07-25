#!/bin/bash

clear
echo -e "\033[1;31m"
cat << "EOF"
 ▄▄▄▄   ██▓   ▄▄▄       ▄████ ▒█████ ▓█████▄ ▄▄▄      ██▀███ ▓█████ ███▄    █ 
▓█████▄▓██▒  ▒████▄    ██▒ ▀█▒██▒  ██▒██▀ ██▒████▄   ▓██ ▒ ██▓█   ▀ ██ ▀█   █ 
▒██▒ ▄█▒██░  ▒██  ▀█▄ ▒██░▄▄▄▒██░  ██░██   █▒██  ▀█▄ ▓██ ░▄█ ▒███  ▓██  ▀█ ██▒
▒██░█▀ ▒██░  ░██▄▄▄▄██░▓█  ██▒██   ██░▓█▄   ░██▄▄▄▄██▒██▀▀█▄ ▒▓█  ▄▓██▒  ▐▌██▒
░▓█  ▀█░██████▓█   ▓██░▒▓███▀░ ████▓▒░▒████▓ ▓█   ▓██░██▓ ▒██░▒████▒██░   ▓██░
░▒▓███▀░ ▒░▓  ▒▒   ▓▒█░░▒   ▒░ ▒░▒░▒░ ▒▒▓  ▒ ▒▒   ▓▒█░ ▒▓ ░▒▓░░ ▒░ ░ ▒░   ▒ ▒ 
▒░▒   ░░ ░ ▒  ░▒   ▒▒ ░ ░   ░  ░ ▒ ▒░ ░ ▒  ▒  ▒   ▒▒ ░ ░▒ ░ ▒░░ ░  ░ ░░   ░ ▒░
 ░    ░  ░ ░   ░   ▒  ░ ░   ░░ ░ ░ ▒  ░ ░  ░  ░   ▒    ░░   ░   ░     ░   ░ ░ 
 ░         ░  ░    ░  ░     ░    ░ ░    ░         ░  ░  ░       ░  ░        ░ 
      ░                               ░                                       
EOF
echo -e "\033[0m"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
debug() { echo -e "[DEBUG] $1"; }

# Функция ожидания освобождения блокировки APT
wait_for_apt_lock() {
    local max_wait=300  # 5 минут
    local wait_time=0
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [ $wait_time -ge $max_wait ]; then
            error "Превышено время ожидания освобождения блокировки APT"
        fi
        
        warning "APT заблокирован другим процессом, ожидание... ($wait_time/$max_wait сек)"
        sleep 10
        wait_time=$((wait_time + 10))
    done
    
    # Дополнительная проверка других блокировок
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $wait_time -ge $max_wait ]; then
            error "Превышено время ожидания освобождения блокировки APT"
        fi
        
        warning "Обнаружены дополнительные блокировки APT, ожидание... ($wait_time/$max_wait сек)"
        sleep 10
        wait_time=$((wait_time + 10))
    done
    
    log "Блокировки APT освобождены"
}

# ======================== Параметры ========================
read -p "Установить BBR и Xanmod Kernel? (y/n): " ans_bbr
if [[ $ans_bbr =~ ^[Yy] ]]; then
    INSTALL_BBR=true
else
    INSTALL_BBR=false
fi

read -p "Настроить SSH ключ? (y/n): " ans_sshkey
if [[ $ans_sshkey =~ ^[Yy] ]]; then
    INSTALL_SSH_KEY=true
else
    INSTALL_SSH_KEY=false
fi

if [[ $EUID -ne 0 ]]; then
   error "Этот скрипт должен быть запущен с правами root"
fi

log "==================== НАЧАЛО УСТАНОВКИ ===================="
log "Этап 0: Сбор необходимых данных..."

# Запрос SSH порта
while true; do
    read -p "Введите порт для SSH (по умолчанию 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
        break
    else
        warning "Некорректный порт. Введите число от 1 до 65535"
    fi
done

# Запрос IP мастер-ноды
while true; do
    read -p "Введите IP адрес мастер-ноды: " MASTER_IP
    if [[ $MASTER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        break
    else
        warning "Некорректный формат IP адреса. Попробуйте снова."
    fi
done

if $INSTALL_SSH_KEY; then
    while true; do
        log "Введите ваш публичный SSH ключ (должен начинаться с 'ssh-rsa' или 'ssh-ed25519'):"
        read SSH_KEY
        if [[ -z "$SSH_KEY" ]]; then
            warning "SSH ключ не может быть пустым."
        elif [[ "$SSH_KEY" =~ ^(ssh-rsa|ssh-ed25519)[[:space:]].*$ ]]; then
            break
        else
            warning "Некорректный формат SSH ключа."
        fi
    done
fi

while true; do
    read -p "Введите субдомен (например, us.domain.com): " SUBDOMAIN
    if [ -z "$SUBDOMAIN" ]; then
        warning "Субдомен не может быть пустым. Пожалуйста, введите значение."
    else
        break
    fi
done

while true; do
    read -p "Введите имя ноды (например, us-node-1): " NODE_NAME
    if [ -z "$NODE_NAME" ]; then
        warning "Имя ноды не может быть пустым. Пожалуйста, введите значение."
    else
        break
    fi
done

# Cloudflare настройки убраны - используем Caddy с автоматическими сертификатами

read -p "Введите порт для сервиса (по умолчанию 62050): " SERVICE_PORT
SERVICE_PORT=${SERVICE_PORT:-62050}
read -p "Введите порт для API (по умолчанию 62051): " API_PORT
API_PORT=${API_PORT:-62051}

# Запрос SSL сертификата
log "Введите SSL client сертификат (После Enter - Ctrl+D для завершения ввода):"
SSL_CERT=$(cat)
if [ -z "$SSL_CERT" ]; then
    error "SSL сертификат не может быть пустым."
fi

# Извлечение тела сертификата (без BEGIN/END)
CERT_BODY=$(echo "$SSL_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')
if [[ ! $CERT_BODY =~ ^[A-Za-z0-9+/=]+$ ]]; then
    error "Некорректный формат сертификата. Пожалуйста, предоставьте валидный SSL сертификат."
fi

debug "Установлены следующие значения:"
debug "Субдомен: ${SUBDOMAIN}"
debug "Название ноды: ${NODE_NAME}"
debug "Service port: ${SERVICE_PORT}"
debug "API port: ${API_PORT}"

# ======================== Установка системных компонентов ========================
log "==================== СИСТЕМНЫЕ КОМПОНЕНТЫ ===================="
log "Этап 1: Установка системных компонентов..."

log "Шаг 1.0: Проверка блокировок APT..."
wait_for_apt_lock

log "Шаг 1.1: Обновление системы..."
apt update 2>&1 | while read -r line; do debug "$line"; done
apt upgrade -y 2>&1 | while read -r line; do debug "$line"; done || error "Ошибка при обновлении системы"

log "Шаг 1.2: Установка базовых пакетов..."
apt install -y curl wget git expect ufw openssl lsb-release ca-certificates gnupg2 ubuntu-keyring 2>&1 | while read -r line; do debug "$line"; done || error "Ошибка при установке базовых пакетов"

# ======================== Опциональная установка BBR ========================
if $INSTALL_BBR; then
    log "==================== УСТАНОВКА BBRv3 ===================="
    log "Шаг 1.3: Установка BBRv3..."
    debug "Загрузка скрипта BBRv3..."
    curl -s https://raw.githubusercontent.com/opiran-club/VPS-Optimizer/main/bbrv3.sh --ipv4 > bbrv3.sh || error "Ошибка при скачивании BBRv3"
    expect << 'EOF'
spawn bash bbrv3.sh
expect "Enter"
send "1\r"
expect "y/n"
send "y\r"
expect eof
EOF
    rm bbrv3.sh
else
    debug "Опциональная установка BBR пропущена."
fi

log "==================== УСТАНОВКА CADDY ===================="
log "Шаг 1.4: Установка Caddy..."

# Добавление официального репозитория Caddy
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update 2>&1 | while read -r line; do debug "$line"; done
apt install -y caddy || error "Ошибка при установке Caddy"

log "==================== НАСТРОЙКА CADDY ===================="
log "Настройка Caddyfile..."

# Создание Caddyfile на основе шаблона
cat > /etc/caddy/Caddyfile << CADDY_EOF
{
  https_port 4123
  default_bind 127.0.0.1
  servers {
    listener_wrappers {
      proxy_protocol {
        allow 127.0.0.1/32
      }
      tls
    }
  }
  auto_https disable_redirects
}

https://${SUBDOMAIN} {
  root * /var/www/${SUBDOMAIN}
  file_server
}

http://${SUBDOMAIN} {
  bind 0.0.0.0
  redir https://{host}{uri} permanent
}

:4123 {
  tls internal
  respond 204
}

:80 {
  bind 0.0.0.0
  respond 204
}
CADDY_EOF

# Создание директории для веб-контента
mkdir -p /var/www/${SUBDOMAIN}
cat > /var/www/${SUBDOMAIN}/index.html << 'HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Storage - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-container { background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0, 0, 0, 0.1); width: 100%; max-width: 400px; }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { color: #333; margin: 0; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #666; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .submit-btn { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .submit-btn:hover { background-color: #0056b3; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>Cloud Storage</h1>
        </div>
        <form action="#" method="POST" onsubmit="return false;">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="submit-btn">Log In</button>
        </form>
        <div class="footer">
            <p>Protected by CloudFlare</p>
        </div>
    </div>
</body>
</html>
HTML_EOF

chown -R caddy:caddy /var/www/${SUBDOMAIN}
chmod -R 755 /var/www/${SUBDOMAIN}

# ======================== Предварительная установка Docker ========================
log "==================== УСТАНОВКА DOCKER ===================="
log "Этап 2: Предварительная установка Docker..."

# Проверка, установлен ли уже Docker
if ! command -v docker &> /dev/null; then
    log "Docker не найден, выполняется установка..."
    wait_for_apt_lock
    
    # Установка Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    chmod +x get-docker.sh
    ./get-docker.sh
    rm -f get-docker.sh
    
    # Запуск и включение Docker
    systemctl enable docker
    systemctl start docker
    
    # Проверка установки
    if ! systemctl is-active --quiet docker; then
        error "Не удалось запустить Docker сервис"
    fi
    
    log "Docker успешно установлен и запущен"
else
    log "Docker уже установлен"
    
    # Убедимся, что Docker запущен
    if ! systemctl is-active --quiet docker; then
        log "Запуск Docker сервиса..."
        systemctl start docker
    fi
fi

# ======================== Установка Marzban Node ========================
log "==================== УСТАНОВКА MARZBAN NODE ===================="
log "Этап 3: Установка Marzban Node..."
curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban-node.sh > marzban-node.sh
chmod +x marzban-node.sh

expect << EOF
spawn ./marzban-node.sh @ install --name ${NODE_NAME}
expect "Please paste the content of the Client Certificate"
send -- "-----BEGIN CERTIFICATE-----\n"
send -- "${CERT_BODY}\n"
send -- "-----END CERTIFICATE-----\n\n"
expect "Do you want to use REST protocol?"
send -- "y\n"
expect "Enter the SERVICE_PORT"
send -- "${SERVICE_PORT}\n"
expect "Enter the XRAY_API_PORT"
send -- "${API_PORT}\n"
expect eof
EOF

rm -f marzban-node.sh

log "Ожидание завершения установки Marzban Node..."
# Даем время установке завершиться
sleep 15

# Убедимся, что Docker сервис запущен и работает
log "Финальная проверка Docker сервиса..."
if ! systemctl is-active --quiet docker; then
    warning "Docker сервис не активен, попытка запуска..."
    systemctl start docker
    sleep 5
    
    if ! systemctl is-active --quiet docker; then
        error "Критическая ошибка: не удалось запустить Docker сервис"
    fi
fi

# Проверка, что команда docker работает
if ! docker --version >/dev/null 2>&1; then
    error "Docker установлен, но команда docker не работает"
fi

log "Docker сервис работает корректно"

mkdir -p /var/lib/marzban/log
touch /var/lib/marzban/log/access.log
chmod 755 /var/lib/marzban/log
chmod 644 /var/lib/marzban/log/access.log

# Проверка различных возможных расположений docker-compose.yml
DOCKER_COMPOSE_FILE=""
POSSIBLE_LOCATIONS=(
    "/opt/${NODE_NAME}/docker-compose.yml"
    "/opt/marzban-node/docker-compose.yml"
    "/opt/marzban-node-${NODE_NAME}/docker-compose.yml"
    "/root/marzban-node/docker-compose.yml"
    "/root/${NODE_NAME}/docker-compose.yml"
)

debug "Поиск docker-compose.yml в следующих местах:"
for location in "${POSSIBLE_LOCATIONS[@]}"; do
    debug "Проверка: $location"
    if [[ -f "$location" ]]; then
        DOCKER_COMPOSE_FILE="$location"
        debug "Найден docker-compose.yml: $location"
        break
    fi
done

# Если не найден в предопределенных местах, попробуем найти через find
if [[ -z "$DOCKER_COMPOSE_FILE" ]]; then
    debug "Поиск docker-compose.yml через find..."
    FOUND_FILES=$(find /opt /root -name "docker-compose.yml" -type f 2>/dev/null | head -5)
    if [[ -n "$FOUND_FILES" ]]; then
        debug "Найденные docker-compose.yml файлы:"
        echo "$FOUND_FILES" | while read -r file; do
            debug "  - $file"
        done
        DOCKER_COMPOSE_FILE=$(echo "$FOUND_FILES" | head -1)
        debug "Используется первый найденный: $DOCKER_COMPOSE_FILE"
    fi
fi

if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
    debug "Настройка монтирования логов в $DOCKER_COMPOSE_FILE"
    COMPOSE_DIR=$(dirname "$DOCKER_COMPOSE_FILE")
    
    # Проверим, есть ли уже монтирование логов
    if ! grep -q "/var/lib/marzban/log" "$DOCKER_COMPOSE_FILE"; then
        sed -i '/volumes:/a\      - /var/lib/marzban/log:/var/lib/marzban/log' "$DOCKER_COMPOSE_FILE"
        debug "Добавлено монтирование логов"
    else
        debug "Монтирование логов уже настроено"
    fi
    
    cd "$COMPOSE_DIR"
    debug "Перезапуск Docker Compose в директории: $COMPOSE_DIR"
    
    # Более надежная остановка контейнеров
    docker compose down 2>/dev/null || true
    sleep 3
    
    # Запуск с повторной попыткой в случае неудачи
    if ! docker compose up -d; then
        warning "Первая попытка запуска не удалась, повторная попытка через 5 секунд..."
        sleep 5
        docker compose up -d
    fi
    
    # Проверка статуса контейнеров
    sleep 5
    log "Статус контейнеров Marzban Node:"
    docker compose ps | while read -r line; do debug "  $line"; done
else
    warning "Файл docker-compose.yml не найден ни в одном из ожидаемых мест, пропуск настройки монтирования логов."
    debug "Список содержимого /opt:"
    ls -la /opt/ 2>/dev/null | while read -r line; do debug "  $line"; done
    debug "Список содержимого /root:"
    ls -la /root/ 2>/dev/null | while read -r line; do debug "  $line"; done
fi

# ======================== Финальные проверки и настройки ========================
log "==================== ФИНАЛЬНЫЕ ПРОВЕРКИ ===================="
log "Проверка конфигурации Caddy..."
caddy validate --config /etc/caddy/Caddyfile 2>&1 | while read -r line; do debug "$line"; done || error "Ошибка в конфигурации Caddy"

systemctl enable caddy 2>&1 | while read -r line; do debug "$line"; done
systemctl start caddy 2>&1 | while read -r line; do debug "$line"; done
if ! systemctl is-active --quiet caddy; then
    error "Не удалось запустить Caddy"
fi

log "Настройка UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow ${SSH_PORT}/tcp
ufw allow from ${MASTER_IP}
echo "y" | ufw enable
ufw status verbose || error "Ошибка при настройке UFW"

log "Настройка SSH..."
if $INSTALL_SSH_KEY; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    cat > /root/.ssh/authorized_keys << KEYS_EOF
${SSH_KEY}
KEYS_EOF

    # Настройка базового конфига SSH
    cat > /etc/ssh/sshd_config << SSH_EOF
Port ${SSH_PORT}
Protocol 2
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
AllowUsers root
SSH_EOF

    systemctl restart ssh
    if ! systemctl is-active --quiet ssh; then
        error "Не удалось запустить SSH"
    fi
fi

log "Установка успешно завершена!"
debug "Все компоненты установлены и настроены"
read -p "Перезагрузить систему сейчас? (y/n): " reboot_now
if [[ $reboot_now == "y" ]]; then
    debug "Выполняется перезагрузка системы..."
    reboot
fi
