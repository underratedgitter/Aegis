# Host-port selection helpers sourced by scripts/start.sh (tested in tests/test_start_ports.py).
#
# A port chosen automatically is saved to the env file the same way start.sh saves
# AEGIS_API_KEY, because `docker compose` reads that file too: without it a later plain
# `docker compose up` would fall back to the default port and fail while it is busy.

ENV_FILE="${ENV_FILE:-.env}"

port_in_use() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$1" >/dev/null 2>&1
  else
    return 1
  fi
}

read_env_value() {
  if [[ -f "$ENV_FILE" ]] && grep -q "^$1=." "$ENV_FILE"; then
    grep "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-
  fi
}

# Set KEY=VALUE in the env file: replace an existing line in place, else append.
persist_env_value() {
  local key="$1" value="$2" tmp
  touch "$ENV_FILE"
  if grep -q "^$key=" "$ENV_FILE"; then
    tmp="$(mktemp)"
    sed "s/^$key=.*/$key=$value/" "$ENV_FILE" >"$tmp"
    cat "$tmp" >"$ENV_FILE"
    rm -f "$tmp"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

# select_port NAME DEFAULT OWN [RESERVED...]
#   Prints the host port to use for NAME and saves it to the env file when it differs from
#   what a plain `docker compose up` would use (the saved value, else DEFAULT).
#   A saved port is reused while it is free; OWN is the port this stack already publishes,
#   which counts as free so re-runs stay stable. Otherwise the first free port from DEFAULT
#   upward is used, skipping RESERVED ports that belong to other Aegis services.
select_port() {
  local name="$1" default="$2" own="$3"
  shift 3
  local reserved=" $* " saved port
  saved="$(read_env_value "$name")"

  _port_usable() {
    [[ "$reserved" != *" $1 "* ]] && { [[ "$1" == "$own" ]] || ! port_in_use "$1"; }
  }

  port="$default"
  if [[ "$saved" =~ ^[0-9]+$ ]] && ((saved >= 1 && saved <= 65535)) && _port_usable "$saved"; then
    port="$saved"
  else
    while ! _port_usable "$port"; do
      port=$((port + 1))
      if ((port > 65535)); then
        echo "No free port found for $name." >&2
        return 1
      fi
    done
  fi

  if [[ "$port" != "${saved:-$default}" ]]; then
    persist_env_value "$name" "$port"
  fi
  echo "$port"
}
