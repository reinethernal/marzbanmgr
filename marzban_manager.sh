#!/usr/bin/env bash
# Marzban manager — единый интерактивный скрипт.
# Меню:
# 1) Установить/переустановить Marzban
# 2) Применить env.vars в /opt/marzban/.env            (пересоздать РАССЛАБЛЕННО)
# 3) Добавить inbound’ы (только объявленные)           (пересоздать СТРОГО)
# 4) Установить валидные шаблоны подписок               (пересоздать РАССЛАБЛЕННО)
# 5) Пересоздать стек (caddy|uvicorn)                  (пересоздать СТРОГО)
# 6) Показать статус
# 7) Добавить ноду Marzban (интерактивный SSH; PEM берётся автоматически через API)
# 0) Выход

set -Eeuo pipefail

die(){
  trap - ERR
  if command -v dialog >/dev/null 2>&1; then
    dialog --msgbox "Ошибка: $*" 10 60 >&2
  else
    echo "Ошибка: $*" >&2
  fi
  exit 1
}
info(){ echo "==> $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

trap 'die "Неожиданная ошибка на строке $LINENO"' ERR

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$BASE_DIR"
ENV_VARS_PATH="${ENV_VARS_PATH:-${1:-./env.vars}}"
COMPOSE_DIR="/opt/marzban"
ENV_FILE="$COMPOSE_DIR/.env"

normalize_file(){ local f="${1:-}"; [ -f "$f" ] || return 0
  sed -i 's/\r$//' "$f" 2>/dev/null || true
  sed -i '1s/^\xEF\xBB\xBF//' "$f" 2>/dev/null || true; }

ensure_cmd(){
  local need="$1"; shift
  have "$need" && return 0
  have apt-get || die "нет apt-get; установите '$need' вручную"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
  local pkg; for pkg in "$@"; do DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" && break || true; done
  have "$need" || die "не удалось установить '$need'"; }

getv_file(){ local f="$1" k="$2"
  [ -f "$f" ] || { echo ""; return 0; }
  normalize_file "$f"
  awk -v RS='\n' -v key="$k" '
    /^[[:space:]]*#/ { next } /^[[:space:]]*$/ { next }
    { line=$0; sub(/^[[:space:]]*export[[:space:]]+/,"",line)
      pos=index(line,"="); if(pos==0) next
      k=substr(line,1,pos-1); v=substr(line,pos+1)
      gsub(/^[[:space:]]+|[[:space:]]+$/,"",k)
      if(k!=key) next
      if(v ~ /^"/){ sub(/^"/,"",v); sub(/"[[:space:]]*$/,"",v) }
      else if(v ~ /^'\''/){ sub(/^'\''/,"",v); sub(/[[:space:]]*'\''$/,"",v) }
      else { sub(/[[:space:]]*#.*$/,"",v); sub(/[[:space:]]+$/,"",v) }
      print v; exit }' "$f"
}
getv(){ local key="$1" v; v="$(getv_file "$ENV_FILE" "$key")"; [ -n "$v" ] || v="$(getv_file "$ENV_VARS_PATH" "$key")"; printf '%s' "$v"; }

set_kv_force(){ local file="$1" key="$2" val="$3"
  ensure_cmd awk gawk mawk
  local qv; qv=$(printf '%s' "$val" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
  sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=/d" "$file"
  printf '%s="%s"\n' "$key" "$qv" >> "$file"
}
del_kv_all(){ local file="$1" key="$2"; sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=/d" "$file"; }

delete_webhook_safe(){
  local tok; tok="$(getv TELEGRAM_API_TOKEN)"
  [ -z "$tok" ] && { echo "==> TELEGRAM_API_TOKEN не задан — пропускаю deleteWebhook"; return 0; }
  ensure_cmd curl curl
  echo "==> Удаляю Telegram webhook"
  curl -sS -X POST "https://api.telegram.org/bot${tok}/deleteWebhook" -d 'drop_pending_updates=true' >/dev/null || true
}

wait_api(){
  ensure_cmd curl curl
  local MODE DOMAIN UDS code; MODE="$(getv TLS_MODE)"; DOMAIN="$(getv DOMAIN)"; UDS="$(getv UVICORN_UDS)"
  [ -n "$UDS" ] || UDS="/var/lib/marzban/marzban.socket"
  local SEC=300 i=0
  if [ "${MODE:-}" = "caddy" ]; then
    local j=0; while [ $j -lt 90 ] && [ ! -S "$UDS" ]; do sleep 1; j=$((j+1)); done
  fi
  while [ $i -lt $SEC ]; do
    if [ -S "$UDS" ]; then
      code=$(curl -sS --unix-socket "$UDS" -m 3 -o /dev/null -w '%{http_code}' "http://localhost/api/system" 2>/dev/null || true)
      [ "$code" -ge 200 ] && [ "$code" -lt 500 ] && { echo "curl -sS --unix-socket $UDS|http://localhost"; return 0; }
    fi
    if [ -n "${DOMAIN:-}" ]; then
      code=$(curl -ksS -m 3 -o /dev/null -w '%{http_code}' "https://${DOMAIN}/api/system" 2>/dev/null || true)
      [ "$code" -ge 200 ] && [ "$code" -lt 500 ] && { echo "curl -ksS|https://${DOMAIN}"; return 0; }
    fi
    code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8000/api/system" 2>/dev/null || true)
    [ "$code" -ge 200 ] && [ "$code" -lt 500 ] && { echo "curl -sS|http://127.0.0.1:8000"; return 0; }
    code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://localhost:8000/api/system" 2>/dev/null || true)
    [ "$code" -ge 200 ] && [ "$code" -lt 500 ] && { echo "curl -sS|http://localhost:8000"; return 0; }
    sleep 1; i=$((i+1))
  done
  return 1
}

get_token_with_admin(){
  ensure_cmd jq jq
  local pair; pair="$(wait_api)" || return 1
  local CURL_CMD="${pair%%|*}"; local BASE="${pair##*|}"
  local U P; U="$(getv SUDO_USERNAME)"; P="$(getv SUDO_PASSWORD)"
  [ -n "$U" ] && [ -n "$P" ] || die "нет SUDO_USERNAME/SUDO_PASSWORD"
  have marzban || true
  if have marzban; then printf '%s\n%s\n%s\n' "$U" "$P" "$P" | marzban cli admin create --sudo >/dev/null 2>&1 || true; fi
  local HTTP; HTTP=$($CURL_CMD -o /tmp/token.json -w "%{http_code}" -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=${U}" --data-urlencode "password=${P}" "$BASE/api/admin/token" 2>/dev/null || true)
  [ "$HTTP" = "200" ] || return 1
  jq -e 'has("access_token")' /tmp/token.json >/dev/null 2>&1 || return 1
  local T; T="$(jq -r '.access_token' /tmp/token.json)"; [ -n "$T" ] && [ "$T" != "null" ] || return 1
  echo "$CURL_CMD|$BASE|Authorization: Bearer $T"
}

ensure_host_network(){
  ensure_cmd awk gawk mawk
  local F="$COMPOSE_DIR/docker-compose.yml"
  [ -f "$F" ] || die "нет $F"
  if ! grep -q '^[[:space:]]*network_mode:[[:space:]]*host[[:space:]]*$' "$F"; then
    cp -a "$F" "${F}.$(date +%Y%m%d-%H%M%S).bak"
    awk 'BEGIN{in_m=0;ins=0}
      /^[[:space:]]*marzban:[[:space:]]*$/ {print;in_m=1;next}
      { if(in_m==1 && ins==0){ print;
          if($0 ~ /^[[:space:]]*(image|restart|environment|depends_on):/){ print "    network_mode: host"; ins=1 }
          if($0 ~ /^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*$/){ in_m=0 } ; next }
        print }' "$F" > "${F}.new" && mv "${F}.new" "$F"
    info "network_mode: host добавлен"
  fi
}

configure_stack_from_env(){
  [ -f "$ENV_FILE" ] || die "нет $ENV_FILE (сначала пункт 1)"
  ensure_host_network
  local MODE
  MODE="$(getv TLS_MODE)"
  if [ -z "$MODE" ]; then
    ensure_cmd dialog dialog
    if ! MODE=$(dialog --clear --stdout --menu "Режим TLS:" 12 50 2 \
        caddy "caddy" \
        uvicorn "uvicorn" ); then
      die "TLS_MODE не выбран"
    fi
    set_kv_force "$ENV_FILE" TLS_MODE "$MODE"
  fi

  case "${MODE:-}" in
    caddy)
      local DOMAIN ACME_EMAIL
      DOMAIN="$(getv DOMAIN)"; ACME_EMAIL="$(getv ACME_EMAIL)"
      [ -n "$DOMAIN" ] || die "TLS_MODE=caddy: нет DOMAIN"
      [ -n "$ACME_EMAIL" ] || die "TLS_MODE=caddy: нет ACME_EMAIL"
      set_kv_force "$ENV_FILE" UVICORN_UDS "/var/lib/marzban/marzban.socket"
      del_kv_all  "$ENV_FILE" UVICORN_HOST
      del_kv_all  "$ENV_FILE" UVICORN_PORT
      del_kv_all  "$ENV_FILE" UVICORN_SSL_CERTFILE
      del_kv_all  "$ENV_FILE" UVICORN_SSL_KEYFILE

      cat > "$COMPOSE_DIR/docker-compose.override.yml" <<'YAML'
services:
  marzban:
    depends_on: [caddy]
  caddy:
    image: caddy:2
    restart: always
    ports: ["80:80","443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - /var/lib/marzban:/var/lib/marzban
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data: {}
  caddy_config: {}
YAML

      cat > "$COMPOSE_DIR/Caddyfile" <<CADDY
{
  email $(getv ACME_EMAIL)
}
$(getv DOMAIN) {
  reverse_proxy unix//var/lib/marzban/marzban.socket
}
CADDY
      ;;
    uvicorn)
      ensure_cmd certbot certbot
      local DOMAIN ACME_EMAIL DIR CERT KEY
      DOMAIN="$(getv DOMAIN)"; ACME_EMAIL="$(getv ACME_EMAIL)"
      [ -n "$DOMAIN" ] || die "TLS_MODE=uvicorn: нет DOMAIN"
      [ -n "$ACME_EMAIL" ] || die "TLS_MODE=uvicorn: нет ACME_EMAIL"
      DIR="/var/lib/marzban/certs/$DOMAIN"; CERT="$DIR/fullchain.pem"; KEY="$DIR/privkey.pem"
      mkdir -p "$DIR"
      if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
        systemctl stop caddy 2>/dev/null || true
        certbot certonly --standalone -d "$DOMAIN" -m "$ACME_EMAIL" --agree-tos --non-interactive --preferred-challenges http \
          || die "certbot: выпуск неудачен (DNS A/порт 80?)"
        cp -L "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT"
        cp -L "/etc/letsencrypt/live/$DOMAIN/privkey.pem"  "$KEY"
        chmod 600 "$KEY"
      fi
      set_kv_force "$ENV_FILE" UVICORN_HOST "0.0.0.0"
      set_kv_force "$ENV_FILE" UVICORN_PORT "8000"
      set_kv_force "$ENV_FILE" UVICORN_SSL_CERTFILE "$CERT"
      set_kv_force "$ENV_FILE" UVICORN_SSL_KEYFILE "$KEY"
      del_kv_all "$ENV_FILE" UVICORN_UDS
      rm -f "$COMPOSE_DIR/docker-compose.override.yml" "$COMPOSE_DIR/Caddyfile" 2>/dev/null || true
      docker rm -f marzban-caddy-1 2>/dev/null || true
      ;;
    *)
      die "Неизвестный TLS_MODE: ${MODE:-<пусто>} (ожидалось uvicorn|caddy)"
      ;;
  esac
}

compose_up_relaxed(){
  delete_webhook_safe
  (cd "$COMPOSE_DIR" && docker compose up -d --force-recreate --remove-orphans)
  if ! pair="$(wait_api)"; then
    echo "Внимание: API не поднялся (продолжаю). Проверьте логи ниже."
    docker logs --tail 100 marzban-marzban-1 2>/dev/null || true
    docker logs --tail 60  marzban-caddy-1  2>/dev/null || true
    return 0
  fi
}
compose_up_force(){
  delete_webhook_safe
  (cd "$COMPOSE_DIR" && docker compose up -d --force-recreate --remove-orphans)
  wait_api >/dev/null || {
    echo "---- marzban (tail 150) ----"; docker logs --tail 150 marzban-marzban-1 2>/dev/null || true
    echo "---- caddy   (tail  80) ----"; docker logs --tail  80 marzban-caddy-1  2>/dev/null || true
    die "API не поднялся"
  }
}
ensure_api_up(){
  [ -d "$COMPOSE_DIR" ] || die "нет $COMPOSE_DIR (сначала пункт 1)"
  (cd "$COMPOSE_DIR" && docker compose up -d --remove-orphans)
  wait_api >/dev/null || {
    docker logs --tail 150 marzban-marzban-1 2>/dev/null || true
    docker logs --tail  80 marzban-caddy-1  2>/dev/null || true
    die "API не поднялся"
  }
}

# === взять клиентский PEM панели через API ===
api_get_node_cert(){
  ensure_cmd jq jq
  local triple CURL_CMD BASE AUTH HTTP
  triple="$(get_token_with_admin)" || { echo "AUTH_FAIL"; return 1; }
  CURL_CMD="${triple%%|*}"; triple="${triple#*|}"; BASE="${triple%%|*}"; AUTH="${triple##*|}"
  HTTP=$($CURL_CMD -o /tmp/node_settings.json -w "%{http_code}" -H "$AUTH" "$BASE/api/node/settings" 2>/dev/null || true)
  [ "$HTTP" = "200" ] || { echo "API_FAIL"; return 1; }
  jq -er '.certificate' /tmp/node_settings.json > /tmp/ssl_client_cert.pem || { echo "JSON_FAIL"; return 1; }
  grep -q "BEGIN CERTIFICATE" /tmp/ssl_client_cert.pem || { echo "BAD_CERT"; return 1; }
  chmod 600 /tmp/ssl_client_cert.pem || true
  echo "/tmp/ssl_client_cert.pem"
}

# ---------- 1) Установить/переустановить ----------
step1_install(){
  exec 3> >(dialog --gauge "Установка/переустановка Marzban" 10 70 0)
  echo 0 >&3
  ensure_cmd bash bash; ensure_cmd curl curl; ensure_cmd jq jq; ensure_cmd sed sed; ensure_cmd grep grep
  ensure_cmd docker docker.io docker-ce
  docker compose version >/dev/null 2>&1 || ensure_cmd docker-compose docker-compose-plugin docker-compose
  echo 20 >&3

  if [ -d "$COMPOSE_DIR" ] || docker ps -a --format '{{.Names}}' | grep -q '^marzban-'; then
    (cd "$COMPOSE_DIR" 2>/dev/null && docker compose down -v --remove-orphans) || true
    docker rm -f marzban-marzban-1 marzban-caddy-1 2>/dev/null || true
    docker network prune -f >/dev/null 2>&1 || true
    docker volume ls -q | grep -E '^marzban' | xargs -r docker volume rm >/dev/null 2>&1 || true
    rm -rf /var/lib/marzban /var/lib/marzban-node "$COMPOSE_DIR" 2>/dev/null || true
  fi
  echo 40 >&3

  INSTALL_SH="/usr/local/bin/marzban-installer.sh"
  curl -fsSL "https://raw.githubusercontent.com/Gozargah/Marzban-scripts/master/marzban.sh" -o "$INSTALL_SH"
  chmod +x "$INSTALL_SH"
  echo 60 >&3

  LOG="/tmp/marzban_install.$(date +%s).log"
  nohup /usr/bin/env bash "$INSTALL_SH" install >>"$LOG" 2>&1 & pid=$!
  echo 70 >&3

  t=0; while [ $t -lt 240 ]; do [ -f "$ENV_FILE" ] && break; sleep 2; t=$((t+2)); done
  [ -f "$ENV_FILE" ] || { tail -n 100 "$LOG" 2>/dev/null || true; die "После установки нет $ENV_FILE"; }
  echo 90 >&3

  (cd "$COMPOSE_DIR" && docker compose down --remove-orphans) >/dev/null 2>&1 || true

  if ps -p "$pid" >/dev/null 2>&1; then kill "$pid" 2>/dev/null || true; sleep 1; ps -p "$pid" >/dev/null 2>&1 && kill -9 "$pid" 2>/dev/null || true; fi
  echo 100 >&3
  exec 3>&-
  dialog --msgbox "Установка завершена (файлы получены, контейнеры остановлены)" 10 60
}

# ---------- 2) Применить env.vars ----------
step2_apply_env(){
  exec 3> >(dialog --gauge "Применение env.vars → $ENV_FILE" 10 70 0)
  echo 0 >&3
  [ -f "$ENV_VARS_PATH" ] || die "нет $ENV_VARS_PATH"
  [ -f "$ENV_FILE" ] || die "нет $ENV_FILE (сначала пункт 1)"
  normalize_file "$ENV_VARS_PATH"; normalize_file "$ENV_FILE"
  cp -a "$ENV_FILE" "$ENV_FILE.$(date +%Y%m%d-%H%M%S).bak"
  echo 40 >&3
  while IFS= read -r raw || [ -n "$raw" ]; do
    raw="$(printf '%s' "$raw" | sed 's/\r$//')"; case "$raw" in ''|'#'*) continue ;; esac
    raw="${raw#export }"; k="${raw%%=*}"; v="${raw#*=}"
    k="$(printf '%s' "$k" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    v="$(printf '%s' "$v" | sed 's/^[[:space:]]*//')"
    if [[ "$v" == \"*\" ]]; then v="${v#\"}"; v="${v%\"}"
    elif [[ "$v" == \'*\' ]]; then v="${v#\'}"; v="${v%\'}"
    else v="$(printf '%s' "$v" | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//')"; fi
    set_kv_force "$ENV_FILE" "$k" "$v"
  done < "$ENV_VARS_PATH"
  echo 70 >&3
  configure_stack_from_env
  compose_up_relaxed
  echo 100 >&3
  exec 3>&-
  dialog --msgbox "env.vars применён" 8 60
}

# ---------- 3) Добавить inbound’ы ----------

# Переопределённая версия с указанием адреса и логированием протоколов
step4_add_inbounds(){
  local LISTEN_ADDR="${1:-0.0.0.0}"
  info "Добавление inbound’ов (только объявленные) для ${LISTEN_ADDR}"
  ensure_cmd jq jq
  [ -f "$ENV_FILE" ] || die "нет $ENV_FILE (сначала 1 и 2)"
  normalize_file "$ENV_VARS_PATH"
  ensure_api_up

  VLESS_PORT="$(getv_file "$ENV_VARS_PATH" VLESS_PORT)"; VLESS_PORT="${VLESS_PORT//[!0-9]/}"
  VMESS_PORT="$(getv_file "$ENV_VARS_PATH" VMESS_PORT)"; VMESS_PORT="${VMESS_PORT//[!0-9]/}"
  TROJAN_PORT="$(getv_file "$ENV_VARS_PATH" TROJAN_PORT)"; TROJAN_PORT="${TROJAN_PORT//[!0-9]/}"
  SS2022_PORT="$(getv_file "$ENV_VARS_PATH" SS2022_PORT 2>/dev/null || true)"; SS2022_PORT="${SS2022_PORT//[!0-9]/}"
  SS_AEAD_PORT="$(getv_file "$ENV_VARS_PATH" SS_AEAD_PORT 2>/dev/null || true)"; SS_AEAD_PORT="${SS_AEAD_PORT//[!0-9]/}"
  SS2022_PSK="$(getv_file "$ENV_VARS_PATH" SS2022_PSK 2>/dev/null || true)"
  SS_AEAD_PASSWORD="$(getv_file "$ENV_VARS_PATH" SS_AEAD_PASSWORD 2>/dev/null || true)"

  local triple CURL_CMD BASE AUTH HTTP
  triple="$(get_token_with_admin)" || die "Авторизация не удалась (API/учётка)"
  CURL_CMD="${triple%%|*}"; triple="${triple#*|}"; BASE="${triple%%|*}"; AUTH="${triple##*|}"

  HTTP=$($CURL_CMD -o /tmp/core.fetch -w "%{http_code}" -H "$AUTH" "$BASE/api/core/config" 2>/dev/null || true)
  [ "$HTTP" = "200" ] || { head -c 200 /tmp/core.fetch; echo; die "GET /api/core/config (HTTP $HTTP)"; }
  jq 'if has("inbounds") then . else . + {inbounds: []} end' /tmp/core.fetch > /tmp/core.json

  have_in(){ local p="$1" port="$2"; jq --arg p "$p" --argjson port "${port:-0}" \
    '[.inbounds[]? | select(.protocol==$p and (.port==$port))] | length' /tmp/core.json; }

  configured=()

  add_vless_tcp(){ local port="$1"; [ -n "$port" ] || return 0
    [ "$(have_in "vless" "$port")" -gt 0 ] && return 0
    jq --argjson port "$port" --arg listen "$LISTEN_ADDR" '
      .inbounds += [ {
        tag: "VLESS TCP (auto)", listen: $listen, port: $port, protocol: "vless",
        settings: { clients: [], decryption: "none" },
        streamSettings: { network: "tcp" },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      } ]' /tmp/core.json > /tmp/core.json.new && mv /tmp/core.json.new /tmp/core.json
    configured+=("VLESS:$port")
  }

  add_vmess_tcp(){ local port="$1"; [ -n "$port" ] || return 0
    [ "$(have_in "vmess" "$port")" -gt 0 ] && return 0
    jq --argjson port "$port" --arg listen "$LISTEN_ADDR" '
      .inbounds += [ {
        tag: "VMESS TCP (auto)", listen: $listen, port: $port, protocol: "vmess",
        settings: { clients: [] },
        streamSettings: { network: "tcp" },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      } ]' /tmp/core.json > /tmp/core.json.new && mv /tmp/core.json.new /tmp/core.json
    configured+=("VMESS:$port")
  }

  add_trojan_tcp(){ local port="$1"; [ -n "$port" ] || return 0
    [ "$(have_in "trojan" "$port")" -gt 0 ] && return 0
    jq --argjson port "$port" --arg listen "$LISTEN_ADDR" '
      .inbounds += [ {
        tag: "TROJAN TCP (auto)", listen: $listen, port: $port, protocol: "trojan",
        settings: { clients: [] },
        streamSettings: { network: "tcp" },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      } ]' /tmp/core.json > /tmp/core.json.new && mv /tmp/core.json.new /tmp/core.json
    configured+=("TROJAN:$port")
  }

  add_ss2022(){ local port="$1" psk="$2"; [ -n "$port" ] || return 0
    [ -n "$psk" ] || { info "SS2022_PORT задан, но нет SS2022_PSK — пропускаю"; return 0; }
    [ "$(have_in "shadowsocks" "$port")" -gt 0 ] && return 0
    jq --argjson port "$port" --arg psk "$psk" --arg listen "$LISTEN_ADDR" '
      .inbounds += [ {
        tag: "SS2022 TCP/UDP (auto)", listen: $listen, port: $port, protocol: "shadowsocks",
        settings: { method: "2022-blake3-chacha20-poly1305", password: $psk, network: "tcp,udp" },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      } ]' /tmp/core.json > /tmp/core.json.new && mv /tmp/core.json.new /tmp/core.json
    configured+=("SS2022:$port")
  }

  add_ss_aead(){ local port="$1" pass="$2"; [ -n "$port" ] || return 0
    [ -n "$pass" ] || { info "SS_AEAD_PORT задан, но нет SS_AEAD_PASSWORD — пропускаю"; return 0; }
    [ "$(have_in "shadowsocks" "$port")" -gt 0 ] && return 0
    jq --argjson port "$port" --arg pass "$pass" --arg listen "$LISTEN_ADDR" '
      .inbounds += [ {
        tag: "SS AEAD 2018 TCP/UDP (auto)", listen: $listen, port: $port, protocol: "shadowsocks",
        settings: { method: "chacha20-ietf-poly1305", password: $pass, network: "tcp,udp" },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      } ]' /tmp/core.json > /tmp/core.json.new && mv /tmp/core.json.new /tmp/core.json
    configured+=("SS_AEAD:$port")
  }

  add_vless_tcp "$VLESS_PORT"
  add_vmess_tcp "$VMESS_PORT"
  add_trojan_tcp "$TROJAN_PORT"
  add_ss2022 "$SS2022_PORT" "$SS2022_PSK"
  add_ss_aead "$SS_AEAD_PORT" "$SS_AEAD_PASSWORD"

  HTTP=$($CURL_CMD -o /tmp/put.json -w "%{http_code}" -X PUT -H "$AUTH" -H "Content-Type: application/json" \
    --data-binary @/tmp/core.json "$BASE/api/core/config" 2>/dev/null || true)
  [ "$HTTP" = "200" ] || { cat /tmp/put.json; die "PUT /api/core/config (HTTP $HTTP)"; }

  HTTP=$($CURL_CMD -o /tmp/restart.json -w "%{http_code}" -X POST -H "$AUTH" "$BASE/api/core/restart" 2>/dev/null || true)
  [ "$HTTP" = "200" ] || { cat /tmp/restart.json; die "POST /api/core/restart (HTTP $HTTP)"; }

  if [ ${#configured[@]} -gt 0 ]; then
    info "Настроены протоколы: ${configured[*]}"
  else
    info "Не настроено ни одного протокола"
  fi
  compose_up_force
}

# ---------- 4) Шаблоны подписок ----------
step5_install_templates(){
  info "Установка валидных шаблонов подписок"
  TDIR="$(getv CUSTOM_TEMPLATES_DIRECTORY)"; [ -n "$TDIR" ] || TDIR="/var/lib/marzban/templates"
  mkdir -p "$TDIR"/{v2ray,singbox,clash,mux,subscription,home}

  cat > "$TDIR/v2ray/default.json" <<'JSON'
{ "dns": { "servers": [] }, "routing": { "rules": [] } }
JSON
  cat > "$TDIR/v2ray/settings.json" <<'JSON'
{ "padding": true }
JSON
  cat > "$TDIR/singbox/default.json" <<'JSON'
{
  "log": { "disabled": true, "level": "error" },
  "dns": { "servers": [{ "address": "https://1.1.1.1/dns-query", "detour": "direct" }] },
  "inbounds": [],
  "outbounds": [
    { "type": "block", "tag": "block" },
    { "type": "direct", "tag": "direct" }
  ]
}
JSON
  cat > "$TDIR/singbox/settings.json" <<'JSON'
{ "tcp_fast_open": true }
JSON
  cat > "$TDIR/clash/default.yml" <<'YML'
proxies: []
proxy-groups: []
rules: []
YML
  cat > "$TDIR/mux/default.json" <<'JSON'
{ "mux": { "enabled": true, "concurrency": 8 } }
JSON
  cat > "$TDIR/subscription/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Subscription</title><h1>Subscription is active</h1>
HTML
  cat > "$TDIR/home/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Home</title><h1>Welcome to Marzban</h1>
HTML
  ensure_cmd jq jq
  local JSON_BODY pair CURL_CMD BASE AUTH HTTP tmp
  JSON_BODY=$(jq -n \
    --arg v2d "$TDIR/v2ray/default.json" \
    --arg v2s "$TDIR/v2ray/settings.json" \
    --arg sbd "$TDIR/singbox/default.json" \
    --arg sbs "$TDIR/singbox/settings.json" \
    --arg cld "$TDIR/clash/default.yml" \
    --arg muxd "$TDIR/mux/default.json" \
    --arg sub "$TDIR/subscription/index.html" \
    --arg home "$TDIR/home/index.html" \
    '{templates:[{name:"v2ray_default",path:$v2d},{name:"v2ray_settings",path:$v2s},{name:"singbox_default",path:$sbd},{name:"singbox_settings",path:$sbs},{name:"clash_default",path:$cld},{name:"mux_default",path:$muxd},{name:"subscription_index",path:$sub},{name:"home_index",path:$home}]}'
  )
  info "Шаблоны установлены → $TDIR"
  compose_up_relaxed
  pair="$(get_token_with_admin)" || echo "Внимание: токен не получен — пропуск POST /api/template"
  if [ -n "${pair:-}" ]; then
    CURL_CMD="${pair%%|*}"; tmp="${pair#*|}"; BASE="${tmp%%|*}"; AUTH="${tmp#*|}"
    ensure_cmd curl curl
    HTTP=$($CURL_CMD -sS -o /tmp/post_template.log -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' --data "$JSON_BODY" "$BASE/api/template" 2>/dev/null || true)
    if [ "$HTTP" = "409" ]; then
      info "шаблоны уже существуют (409)"
    elif [ "$HTTP" -lt 200 ] || [ "$HTTP" -ge 300 ]; then
      echo "Внимание: POST /api/template → HTTP $HTTP"
    fi
  fi
  local DOMAIN URL CODE
  DOMAIN="$(getv DOMAIN)"
  if [ -n "$DOMAIN" ]; then
    ensure_cmd curl curl
    URL="${DOMAIN}/sub/"
    CODE=$(curl -sS -I -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || true)
    if [ "$CODE" -lt 200 ] || [ "$CODE" -ge 400 ]; then
      echo "Внимание: curl -I $URL → HTTP $CODE"
    fi
  fi
}

# ---------- 5) Пересоздать стек ----------
step3_force_recreate(){
  info "Пересоздание стека (TLS_MODE из .env/env.vars)"
  [ -f "$ENV_FILE" ] || die "нет $ENV_FILE (сначала 1 и 2)"
  configure_stack_from_env
  compose_up_force
}

# ---------- 6) Статус ----------
status(){
  echo "---- docker compose ps ----"
  (cd "$COMPOSE_DIR" 2>/dev/null && docker compose ps) || true
  echo "---- UVICORN effective ----"
  [ -f "$ENV_FILE" ] && grep -E '^(UVICORN_(UDS|HOST|PORT|SSL_CERTFILE|SSL_KEYFILE))=' "$ENV_FILE" || true
  echo "---- UDS socket ----"
  UDS="$(getv UVICORN_UDS)"; [ -z "$UDS" ] && UDS="/var/lib/marzban/marzban.socket"
  ls -l "$UDS" 2>/dev/null || echo "(нет сокета $UDS)"
  echo "---- curl API (UDS) ----"
  curl -sS --unix-socket "$UDS" -m 3 -o - "http://localhost/api/system" 2>/dev/null || true
  echo
  DOMAIN="$(getv DOMAIN)"
  if [ -n "$DOMAIN" ]; then
    echo "---- curl API (https://${DOMAIN}) ----"
    curl -ksS -m 3 -o - "https://${DOMAIN}/api/system" 2>/dev/null || true
    echo
  fi
  echo "---- caddy logs (tail 50) ----"; docker logs --tail 50 marzban-caddy-1 2>/dev/null || true
  echo "---- marzban logs (tail 80) ----"; docker logs --tail 80 marzban-marzban-1 2>/dev/null || true
}

# ---------- 7) Добавить ноду (интерактив SSH; PEM автоматически из API) ----------
step7_add_node(){
  info "Добавление узла (Node) автоматически: PEM берётся из панели через API"

  ensure_cmd ssh openssh-client ssh
  ensure_cmd scp openssh-client scp
  ensure_cmd jq jq
  ensure_cmd dialog dialog

  [ -f "$ENV_FILE" ] || die "нет $ENV_FILE (сначала 1 и 2)"
  ensure_api_up

  # ---- Интерактивный ввод SSH-параметров ----
  if ! SSH_HOST=$(dialog --clear --stdout --inputbox "SSH хост (IP/домен узла):" 8 60); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi
  [ -n "$SSH_HOST" ] || die "SSH хост обязателен"

  if ! SSH_USER=$(dialog --clear --stdout --inputbox "SSH пользователь:" 8 60 "root"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! SSH_PORT=$(dialog --clear --stdout --inputbox "SSH порт:" 8 60 "22"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! AUTH_CHOICE=$(dialog --clear --stdout --menu "Метод аутентификации:" 15 50 2 \
    1 "Пароль" \
    2 "Приватный ключ"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi
  AUTH_CHOICE="${AUTH_CHOICE:-1}"

  SSH_KEY=""; SSH_PASS=""
  if [ "$AUTH_CHOICE" = "2" ]; then
    if ! SSH_KEY=$(dialog --clear --stdout --inputbox "Путь к приватному ключу:" 8 60 "/root/.ssh/id_rsa"); then
      dialog --msgbox "Отменено" 6 40
      return 0
    fi
    [ -f "$SSH_KEY" ] || die "Нет файла ключа: $SSH_KEY"
    chmod 600 "$SSH_KEY" || true
  else
    ensure_cmd sshpass sshpass sshpass
    if ! SSH_PASS=$(dialog --clear --stdout --passwordbox "SSH пароль:" 8 60); then
      dialog --msgbox "Отменено" 6 40
      return 0
    fi
    [ -n "$SSH_PASS" ] || die "Пустой пароль недопустим"
  fi

  # ---- Интерактивные параметры узла ----
  if ! NAME=$(dialog --clear --stdout --inputbox "Имя узла:" 8 60 "node-${SSH_HOST}"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! ADDRESS=$(dialog --clear --stdout --inputbox "Адрес узла (IP/домен):" 8 60 "${SSH_HOST}"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! PORT=$(dialog --clear --stdout --inputbox "SERVICE_PORT:" 8 60 "62050"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! API_PORT=$(dialog --clear --stdout --inputbox "XRAY_API_PORT:" 8 60 "62051"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  if ! PROTO=$(dialog --clear --stdout --menu "SERVICE_PROTOCOL:" 12 50 2 \
    rest "rest" \
    rpyc "rpyc"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi
  PROTO="${PROTO:-rest}"

  if ! ADDH_CHOICE=$(dialog --clear --stdout --menu "Добавлять адрес узла во все инбаунды как host?" 12 60 2 \
    Y "Да" \
    N "Нет"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi
  case "$ADDH_CHOICE" in N) ADDHOST=false ;; *) ADDHOST=true ;; esac

  if ! COEF=$(dialog --clear --stdout --inputbox "usage_coefficient:" 8 60 "1"); then
    dialog --msgbox "Отменено" 6 40
    return 0
  fi

  exec 3> >(dialog --gauge "Развёртывание ноды" 10 70 0)
  echo 0 >&3
  # 1) Получаем PEM панели через API
  local PEM_PATH
  if ! PEM_PATH="$(api_get_node_cert)"; then
    exec 3>&-
    die "Не удалось получить PEM от панели через /api/node/settings. Проверьте доступность API и SUDO_*"
  fi
  echo 25 >&3

  # 2) Регистрируем ноду в панели
  local triple CURL_CMD BASE AUTH HTTP
  triple="$(get_token_with_admin)" || die "Авторизация не удалась (API/учётка)"
  CURL_CMD="${triple%%|*}"; triple="${triple#*|}"; BASE="${triple%%|*}"; AUTH="${triple##*|}"

  cat > /tmp/node.json <<JSON
{"name":"${NAME}","address":"${ADDRESS}","port":${PORT},"api_port":${API_PORT},"add_as_new_host":$( $ADDHOST && echo true || echo false ),"usage_coefficient":${COEF}}
JSON

  HTTP=$($CURL_CMD -o /tmp/node.out -w "%{http_code}" -X POST -H "$AUTH" -H "Content-Type: application/json" \
    --data-binary @/tmp/node.json "$BASE/api/node" 2>/dev/null || true)
  if [ "$HTTP" != "200" ] && [ "$HTTP" != "409" ]; then
    exec 3>&-
    cat /tmp/node.out
    die "POST /api/node (HTTP $HTTP)"
  fi
  echo 50 >&3

  # 3) Копирование PEM и деплой node (ВНИМАНИЕ: для scp порт -P, для ssh порт -p)
  echo 75 >&3

  if [ -n "$SSH_KEY" ]; then
    ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "mkdir -p /var/lib/marzban-node && chmod 700 /var/lib/marzban-node" >/dev/null
    scp -P "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "$PEM_PATH" "${SSH_USER}@${SSH_HOST}:/var/lib/marzban-node/ssl_client_cert.pem" >/dev/null
    ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "chmod 600 /var/lib/marzban-node/ssl_client_cert.pem" >/dev/null
  else
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "mkdir -p /var/lib/marzban-node && chmod 700 /var/lib/marzban-node" >/dev/null
    sshpass -p "$SSH_PASS" scp -P "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "$PEM_PATH" "${SSH_USER}@${SSH_HOST}:/var/lib/marzban-node/ssl_client_cert.pem" >/dev/null
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "chmod 600 /var/lib/marzban-node/ssl_client_cert.pem" >/dev/null
  fi

  # 4) docker-compose.yml на узле и запуск
  read -r -d '' REMOTE_SH <<EOF || true
set -e
if [ "\$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo -n"; else SUDO=""; fi
\$SUDO apt-get update -y || true
\$SUDO apt-get install -y curl socat git ca-certificates >/dev/null 2>&1 || true
if ! command -v docker >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; fi
\$SUDO apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
mkdir -p ~/Marzban-node
cat > ~/Marzban-node/docker-compose.yml <<YAML
services:
  marzban-node:
    image: gozargah/marzban-node:latest
    restart: always
    network_mode: host
    environment:
      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/ssl_client_cert.pem"
      SERVICE_PROTOCOL: "${PROTO}"
      SERVICE_PORT: ${PORT}
      XRAY_API_PORT: ${API_PORT}
    volumes:
      - /var/lib/marzban-node:/var/lib/marzban-node
YAML
cd ~/Marzban-node
DCMD="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then DCMD="docker-compose"; fi
fi
\$DCMD up -d
sleep 2
docker ps --format '{{.Names}}' | grep -qi 'marzban-node' || \$DCMD up -d
EOF

  if [ -n "$SSH_KEY" ]; then
    echo "$REMOTE_SH" | ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" 'bash -s' >/dev/null
  else
    echo "$REMOTE_SH" | sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" 'bash -s' >/dev/null
  fi

  # 5) Конфигурация inbound'ов на главной панели
  step4_add_inbounds "$ADDRESS"

  echo 90 >&3
  echo "---- Проверка узла (docker ps) ----"
  if [ -n "$SSH_KEY" ]; then
    ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "docker ps --format '{{.Names}}  {{.Image}}  {{.Status}}' | grep -i marzban-node" || true
    echo "---- Проверка портов ----"
    ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "ss -tpln 2>/dev/null | grep -E ':(^|.*)(${PORT}|${API_PORT})(\\b|:)' || true" || true
  else
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "docker ps --format '{{.Names}}  {{.Image}}  {{.Status}}' | grep -i marzban-node" || true
    echo "---- Проверка портов ----"
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" -o PreferredAuthentications=password \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${SSH_USER}@${SSH_HOST}" "ss -tpln 2>/dev/null | grep -E ':(^|.*)(${PORT}|${API_PORT})(\\b|:)' || true" || true
  fi

  echo 100 >&3
  exec 3>&-
  dialog --msgbox "Узел развернут, PEM загружен автоматически." 8 60
}

# ---------- Меню ----------
main_menu(){
  normalize_file "$ENV_VARS_PATH"
  ensure_cmd dialog dialog
  while true; do
    choice=$(dialog --clear --stdout --menu "Marzban Manager" 20 70 10 \
      1 "Установить/переустановить Marzban" \
      2 "Применить env.vars в /opt/marzban/.env" \
      3 "Добавить inbound’ы (только объявленные)" \
      4 "Установить валидные шаблоны подписок (sing-box/v2ray/clash/mux)" \
      5 "Пересоздать стек (caddy|uvicorn)" \
      6 "Показать статус" \
      7 "Добавить ноду Marzban" \
      0 "Выход") || break
    case "$choice" in
      1) step1_install ;;
      2) step2_apply_env ;;
      3) step4_add_inbounds ;;
      4) step5_install_templates ;;
      5) step3_force_recreate ;;
      6) status ;;
      7) step7_add_node ;;
      0) break ;;
    esac
  done
}

[ "$(id -u)" -eq 0 ] || die "нужен root"
main_menu
