#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

HOST="0.0.0.0"
PORT="8000"
UVICORN_WORKERS="1"
ADMIN_KEY="${WRAPT_WEBUI_ACCESS_KEY:-}"

AUTO_INSTALL="1"
HEALTH_CHECK="1"
REQUIRE_KALI="1"
SKIP_PIP_INSTALL="0"
STRICT_DEPS="0"
AUTO_START_SERVICES="1"
AI_WARMUP="1"
AUTO_INSTALL_YAK="1"
BOOTSTRAP_ONLY="${WRAPT_BOOTSTRAP_ONLY:-0}"
SERVICE_REGISTER="1"
SERVICE_RUNTIME="${WRAPT_SERVICE_MANAGED:-0}"
SERVICE_NAME="${WRAPT_SERVICE_NAME:-wrapt}"
SERVICE_USER="${WRAPT_SERVICE_USER:-}"
SERVICE_GROUP="${WRAPT_SERVICE_GROUP:-}"
SERVICE_DESCRIPTION="WRAPT Web Service"
SERVICE_UNIT_PATH=""
SERVICE_ENV_PATH=""
VENV_PYTHON=""

VENV_DIR=".venv"
PYTHON_BIN="python3"
OS_FAMILY="unknown"
DISTRO_ID="unknown"
DISTRO_NAME="unknown"
DISTRO_LIKE=""
DISTRO_FLAVOR="unknown"
PACKAGE_MANAGER=""
PACKAGE_UPDATE_DONE="0"
APT_FIX_BROKEN_DONE="0"
SYSTEM_MISSING_DEPS=()

log() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok() { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }
has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_pkg_installed() {
  local pkg="$1"
  [[ -z "$pkg" ]] && return 1
  case "$PACKAGE_MANAGER" in
    apt) dpkg -s "$pkg" 2>/dev/null | grep -q "Status: install ok installed" ;;
    dnf|yum) rpm -q "$pkg" >/dev/null 2>&1 ;;
    brew) brew list "$pkg" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

die() {
  err "$*"
  exit 1
}

usage() {
  cat <<'EOF'
用法: ./start.sh [选项]

选项:
  --host <addr>            绑定主机地址 (默认: 0.0.0.0)
  --port <port>            绑定端口 (默认: 8000)
  --workers <num>          Uvicorn 工作进程数 (默认: 1)
  --admin-key <key>        为本次运行设置 WRAPT_WEBUI_ACCESS_KEY
  --venv <path>            虚拟环境路径 (默认: .venv)
  --python <bin>           Python 执行文件 (默认: python3)

  --no-auto-install        禁用自动安装系统依赖与工具
  --no-health-check        禁用启动后的健康检查
  --skip-pip-install       跳过 pip install -r requirements.txt
  --strict-deps            当依赖项安装/检查失败时终止启动
  --no-auto-services       不自动启动 postgresql/msfdb
  --no-service-register    健康检查通过后不注册 systemd 服务
  --service-runtime        以 systemd 托管模式运行，跳过服务注册
  --service-name <name>    systemd 服务名 (默认: wrapt)
  --service-user <user>    systemd 服务运行用户 (默认: 当前用户)
  --service-group <group>  systemd 服务运行组 (默认: 同 service-user)
  --no-ai-warmup           跳过 Agent/RAG 预热检查
  --no-yak-install         不自动安装 yak 运行时
  --allow-non-kali         允许在非 Kali Linux 上启动
  -h, --help               显示此帮助信息
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --workers) UVICORN_WORKERS="${2:-}"; shift 2 ;;
    --admin-key) ADMIN_KEY="${2:-}"; shift 2 ;;
    --venv) VENV_DIR="${2:-}"; shift 2 ;;
    --python) PYTHON_BIN="${2:-}"; shift 2 ;;
    --no-auto-install) AUTO_INSTALL="0"; shift ;;
    --no-health-check) HEALTH_CHECK="0"; shift ;;
    --skip-pip-install) SKIP_PIP_INSTALL="1"; shift ;;
    --strict-deps) STRICT_DEPS="1"; shift ;;
    --no-auto-services) AUTO_START_SERVICES="0"; shift ;;
    --no-service-register) SERVICE_REGISTER="0"; shift ;;
    --service-runtime) SERVICE_RUNTIME="1"; shift ;;
    --service-name) SERVICE_NAME="${2:-}"; shift 2 ;;
    --service-user) SERVICE_USER="${2:-}"; shift 2 ;;
    --service-group) SERVICE_GROUP="${2:-}"; shift 2 ;;
    --no-ai-warmup) AI_WARMUP="0"; shift ;;
    --no-yak-install) AUTO_INSTALL_YAK="0"; shift ;;
    --allow-non-kali) REQUIRE_KALI="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知选项: $1" ;;
  esac
done

[[ -n "$HOST" ]] || die "host 不能为空"
[[ -n "$PORT" ]] || die "port 不能为空"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  die "port 必须是 1..65535 之间的整数"
fi

if ! [[ "$UVICORN_WORKERS" =~ ^[0-9]+$ ]] || ((UVICORN_WORKERS < 1)); then
  die "workers 必须是正整数"
fi

if [[ -z "$SERVICE_NAME" ]]; then
  die "service-name 不能为空"
fi

append_unique_dep() {
  local dep="$1"
  local existing
  for existing in "${SYSTEM_MISSING_DEPS[@]:-}"; do
    [[ "$existing" == "$dep" ]] && return 0
  done
  SYSTEM_MISSING_DEPS+=("$dep")
}

detect_package_manager() {
  if [[ "$OS_FAMILY" == "linux" ]]; then
    if [[ "$DISTRO_FLAVOR" == "debian" ]] && has_cmd apt-get; then
      PACKAGE_MANAGER="apt"
    elif has_cmd apt-get; then
      PACKAGE_MANAGER="apt"
    fi
  fi
}

detect_platform() {
  local uname_out
  uname_out="$(uname -s 2>/dev/null || echo unknown)"
  case "$uname_out" in
    Linux) OS_FAMILY="linux" ;;
    *) OS_FAMILY="unsupported" ;;
  esac

  if [[ "$OS_FAMILY" == "linux" && -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    local distro_scope=" ${DISTRO_ID} ${DISTRO_LIKE} "
    
    # 严格匹配 Kali, Debian, Ubuntu
    if [[ "$distro_scope" == *" ubuntu "* || "$distro_scope" == *" debian "* || "$distro_scope" == *" kali "* ]]; then
      DISTRO_FLAVOR="debian"
    else
      DISTRO_FLAVOR="unsupported"
    fi
  fi

  detect_package_manager

  if [[ "$OS_FAMILY" == "linux" ]]; then
    log "检测到操作系统: ${DISTRO_NAME}"
    log "检测到包管理器: ${PACKAGE_MANAGER:-未找到}"
    
    if [[ "$DISTRO_FLAVOR" == "unsupported" ]]; then
      echo -e "\033[31m[错误] 雾刃平台目前仅支持以下操作系统：\033[0m"
      echo -e "  - Kali Linux"
      echo -e "  - Debian"
      echo -e "  - Ubuntu"
      echo -e "\n当前检测结果: ${DISTRO_NAME:-未知系统} ($OS_FAMILY / $DISTRO_ID)"
      exit 1
    fi
    
    if [[ "$REQUIRE_KALI" == "1" && "$DISTRO_ID" != "kali" ]]; then
      warn "当前系统不是 Kali，将按跨发行版流程继续准备环境"
    fi
  else
    die "错误：本程序仅支持 Linux 操作系统。"
  fi
}

run_with_privilege() {
  if [[ "${1:-}" == "brew" ]]; then
    shift
    "$@"
    return $?
  fi

  if is_root; then
    shift
    "$@"
  elif has_cmd sudo; then
    sudo "${@:2}"
  else
    return 1
  fi
}

resolve_system_package() {
  local dep="$1"
  case "${PACKAGE_MANAGER}:${dep}" in
    apt:python) echo "python3" ;;
    apt:python_pip) echo "python3-pip" ;;
    apt:python_venv) echo "python3-venv" ;;
    apt:curl) echo "curl" ;;
    apt:git) echo "git" ;;
    apt:unzip) echo "unzip" ;;
    apt:tar) echo "tar" ;;
    apt:gzip) echo "gzip" ;;
    dnf:python|yum:python) echo "python3" ;;
    dnf:python_pip|yum:python_pip) echo "python3-pip" ;;
    dnf:python_venv|yum:python_venv) echo "python3-virtualenv" ;;
    dnf:curl|yum:curl) echo "curl" ;;
    dnf:git|yum:git) echo "git" ;;
    dnf:unzip|yum:unzip) echo "unzip" ;;
    dnf:tar|yum:tar) echo "tar" ;;
    dnf:gzip|yum:gzip) echo "gzip" ;;
    brew:python|brew:python_pip) echo "python" ;;
    brew:curl) echo "curl" ;;
    brew:git) echo "git" ;;
    brew:unzip) echo "unzip" ;;
    brew:tar) echo "gnu-tar" ;;
    brew:gzip) echo "gzip" ;;
    *) echo "" ;;
  esac
}

install_packages() {
  local packages=("$@")
  local package
  local -a to_install=()

  for package in "${packages[@]}"; do
    [[ -n "$package" ]] || continue
    if ! is_pkg_installed "$package"; then
      to_install+=("$package")
    fi
  done

  [[ "${#to_install[@]}" -gt 0 ]] || return 0

  case "$PACKAGE_MANAGER" in
    apt)
      if [[ "$PACKAGE_UPDATE_DONE" != "1" ]]; then
        if ! run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get update -y; then
          return 1
        fi
        PACKAGE_UPDATE_DONE="1"
      fi
      run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
      ;;
    dnf)
      run_with_privilege dnf dnf install -y "${to_install[@]}"
      ;;
    yum)
      run_with_privilege yum yum install -y "${to_install[@]}"
      ;;
    brew)
      brew install "${to_install[@]}"
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_system_command() {
  local cmd="$1"
  local dep="$2"
  if has_cmd "$cmd"; then
    ok "找到依赖项: $cmd"
  else
    warn "缺失依赖项: $cmd"
    append_unique_dep "$dep"
  fi
}

install_missing_system_dependencies() {
  local dep package
  local -a packages=()

  if [[ "${#SYSTEM_MISSING_DEPS[@]}" -eq 0 ]]; then
    return 0
  fi

  if [[ "$AUTO_INSTALL" != "1" ]]; then
    warn "已禁用自动安装，缺失系统依赖: ${SYSTEM_MISSING_DEPS[*]}"
    [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且系统依赖缺失"
    return 0
  fi

  if [[ -z "$PACKAGE_MANAGER" ]]; then
    warn "未找到可用包管理器，无法自动安装系统依赖: ${SYSTEM_MISSING_DEPS[*]}"
    [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且无法自动安装系统依赖"
    return 0
  fi

  for dep in "${SYSTEM_MISSING_DEPS[@]}"; do
    package="$(resolve_system_package "$dep")"
    if [[ -z "$package" ]]; then
      warn "当前包管理器 ${PACKAGE_MANAGER} 未配置系统依赖映射: ${dep}"
      [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且系统依赖映射缺失: ${dep}"
      continue
    fi
    packages+=("$package")
  done

  if [[ "${#packages[@]}" -gt 0 ]]; then
    log "尝试自动安装系统依赖: ${packages[*]}"
    if ! install_packages "${packages[@]}"; then
      warn "系统依赖自动安装失败，请手动安装: ${packages[*]}"
      [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且系统依赖自动安装失败"
    else
      ok "系统依赖安装完成"
    fi
  fi
}

ensure_python_venv_support() {
  if "$PYTHON_BIN" -c "import ensurepip" >/dev/null 2>&1; then
    return 0
  fi

  warn "当前 Python 缺少 ensurepip，虚拟环境创建可能失败"
  local -a candidates=()
  local package

  case "$PACKAGE_MANAGER" in
    apt)
      candidates=("python${PY_VERSION}-venv" "python3-venv")
      ;;
    dnf|yum)
      candidates=("python${PY_VERSION/./}-virtualenv" "python3-virtualenv")
      ;;
    *)
      package="$(resolve_system_package python_venv)"
      [[ -n "$package" ]] && candidates=("$package")
      ;;
  esac

  if [[ "$AUTO_INSTALL" != "1" || -z "$PACKAGE_MANAGER" || "${#candidates[@]}" -eq 0 ]]; then
    warn "请手动安装 venv 组件后重试（例如 Debian/Ubuntu: apt install python${PY_VERSION}-venv）"
    [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且 Python venv 组件缺失"
    return 0
  fi

  for package in "${candidates[@]}"; do
    [[ -n "$package" ]] || continue
    log "尝试安装 Python venv 组件: ${package}"
    if install_packages "$package"; then
      ok "已安装 Python venv 组件: ${package}"
      break
    fi
  done

  if ! "$PYTHON_BIN" -c "import ensurepip" >/dev/null 2>&1; then
    warn "自动安装后仍缺少 ensurepip，请手动安装 python venv 组件"
    [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且 ensurepip 不可用"
  fi
}

ensure_yak_on_path() {
  if has_cmd yak; then
    return 0
  fi

  local candidates=(
    "/usr/local/bin/yak"
    "/usr/bin/yak"
    "$HOME/yak/yak"
    "$HOME/.yak/yak"
  )
  local candidate

  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      export PATH="$(dirname "$candidate"):$PATH"
      return 0
    fi
  done

  return 1
}

check_ui_assets() {
  local required=(
    "webui/static/index.html"
    "webui/static/styles/app.css"
    "webui/static/styles/tailwind.generated.css"
    "webui/static/scripts/app.js"
  )
  local missing=()
  local rel_path

  for rel_path in "${required[@]}"; do
    if [[ ! -f "$rel_path" ]]; then
      missing+=("$rel_path")
    fi
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    err "UI 静态资源检查失败。缺失文件:"
    for rel_path in "${missing[@]}"; do
      err "  - $rel_path"
    done
    return 1
  fi

  ok "UI 静态资源检查通过"
}

health_check() {
  local base_url="http://127.0.0.1:${PORT}"

  curl -fsS --max-time 3 "$base_url/" >/dev/null 2>&1
  curl -fsS --max-time 3 "$base_url/styles/app.css" >/dev/null 2>&1
  curl -fsS --max-time 3 "$base_url/scripts/app.js" >/dev/null 2>&1

  curl -fsS --max-time 3 "$base_url/api/projects" >/dev/null 2>&1
}

service_unit_exists() {
  has_cmd systemctl || return 1
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "${SERVICE_NAME}.service"
}

service_is_active() {
  has_cmd systemctl || return 1
  systemctl is-active --quiet "${SERVICE_NAME}.service"
}

systemd_is_available() {
  has_cmd systemctl && [[ -d /run/systemd/system ]]
}

wait_for_health_check() {
  local attempts="${1:-30}"
  local label="${2:-服务}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if health_check; then
      ok "${label}健康检查通过 (API + UI 静态资源)"
      return 0
    fi
    log "正在等待${label}就绪... (${attempt}/${attempts})"
    sleep 1
  done
  return 1
}

resolve_service_identity() {
  local detected_user detected_group
  detected_user="$(id -un)"
  detected_group="$(id -gn)"

  if [[ -z "$SERVICE_USER" ]]; then
    if is_root && [[ -n "${SUDO_USER:-}" ]]; then
      SERVICE_USER="$SUDO_USER"
    else
      SERVICE_USER="$detected_user"
    fi
  fi

  if [[ -z "$SERVICE_GROUP" ]]; then
    SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || true)"
    [[ -n "$SERVICE_GROUP" ]] || SERVICE_GROUP="$detected_group"
  fi

  SERVICE_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
  SERVICE_ENV_PATH="/etc/default/${SERVICE_NAME}"
}

preserve_existing_service_admin_key() {
  [[ -n "$ADMIN_KEY" ]] && return 0
  [[ -r "$SERVICE_ENV_PATH" ]] || return 0
  ADMIN_KEY="$(
    python - "$SERVICE_ENV_PATH" <<'PY'
import sys

path = sys.argv[1]
for raw_line in open(path, "r", encoding="utf-8"):
    line = raw_line.strip()
    if not line or line.startswith("#") or not line.startswith("WRAPT_WEBUI_ACCESS_KEY="):
        continue
    value = line.split("=", 1)[1].strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = bytes(value[1:-1], "utf-8").decode("unicode_escape")
    print(value)
    break
PY
  )"
}

print_service_recovery_path() {
  local unit_name="${SERVICE_NAME}.service"
  warn "如需恢复，请按顺序执行以下命令："
  warn "  1) sudo systemctl status ${unit_name} --no-pager -l"
  warn "  2) sudo journalctl -u ${unit_name} -n 200 --no-pager"
  warn "  3) sudo systemctl disable --now ${unit_name}"
  warn "  4) sudo rm -f ${SERVICE_UNIT_PATH} ${SERVICE_ENV_PATH}"
  warn "  5) sudo systemctl daemon-reload"
  warn "  6) sudo systemctl reset-failed ${unit_name}"
}

materialize_systemd_service_files() {
  local json_output
  local -a command=(
    env
    "PYTHONPATH=$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
    "$VENV_PYTHON"
    -m
    core.utils.service_manager
    materialize
    --service-name
    "$SERVICE_NAME"
    --root-dir
    "$ROOT_DIR"
    --script-path
    "$ROOT_DIR/start.sh"
    --unit-path
    "$SERVICE_UNIT_PATH"
    --env-path
    "$SERVICE_ENV_PATH"
    --host
    "$HOST"
    --port
    "$PORT"
    --workers
    "$UVICORN_WORKERS"
    --venv-dir
    "$VENV_DIR"
    --python-bin
    "$PYTHON_BIN"
    --service-user
    "$SERVICE_USER"
    --service-group
    "$SERVICE_GROUP"
    --description
    "$SERVICE_DESCRIPTION"
  )

  if [[ -n "$ADMIN_KEY" ]]; then
    command+=(--admin-key "$ADMIN_KEY")
  fi
  if [[ "$REQUIRE_KALI" == "0" ]]; then
    command+=(--allow-non-kali)
  fi
  if [[ "$AUTO_START_SERVICES" == "0" ]]; then
    command+=(--no-auto-services)
  fi

  json_output="$(run_with_privilege svc "${command[@]}")" || return 1

  if python - "$json_output" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
print(f"UNIT_CHANGED={'1' if payload.get('unit_changed') else '0'}")
print(f"ENV_CHANGED={'1' if payload.get('env_changed') else '0'}")
PY
  then
    return 0
  fi
  return 1
}

reconcile_systemd_service() {
  local unit_name="${SERVICE_NAME}.service"
  local metadata

  resolve_service_identity
  preserve_existing_service_admin_key

  if [[ "$HEALTH_CHECK" != "1" ]]; then
    warn "当前已禁用健康检查，跳过 systemd 服务注册"
    return 0
  fi

  if ! systemd_is_available; then
    err "当前环境缺少 systemd，无法完成服务化部署"
    print_service_recovery_path
    return 1
  fi

  log "正在生成 systemd 服务文件: ${unit_name}"
  if ! metadata="$(materialize_systemd_service_files)"; then
    err "systemd 服务文件生成失败"
    print_service_recovery_path
    return 1
  fi
  eval "$metadata"

  if [[ "${UNIT_CHANGED:-0}" == "1" || "${ENV_CHANGED:-0}" == "1" ]]; then
    log "检测到 systemd 配置变更，正在执行 daemon-reload"
    run_with_privilege svc systemctl daemon-reload || {
      err "systemctl daemon-reload 失败"
      print_service_recovery_path
      return 1
    }
  fi

  log "正在启用开机自启: ${unit_name}"
  run_with_privilege svc systemctl enable "$unit_name" >/dev/null || {
    err "启用开机自启失败: ${unit_name}"
    print_service_recovery_path
    return 1
  }

  log "正在重启 systemd 服务: ${unit_name}"
  run_with_privilege svc systemctl restart "$unit_name" || {
    err "启动/重启 systemd 服务失败: ${unit_name}"
    print_service_recovery_path
    return 1
  }

  if ! wait_for_health_check 30 "systemd 托管服务"; then
    err "systemd 托管服务启动后健康检查失败"
    print_service_recovery_path
    return 1
  fi

  ok "systemd 服务已注册并设置为开机自启: ${unit_name}"
  ok "服务文件: ${SERVICE_UNIT_PATH}"
  ok "环境文件: ${SERVICE_ENV_PATH}"
}

install_package_best_effort() {
  local package="$1"
  [[ -n "$package" ]] || return 0
  
  if is_pkg_installed "$package"; then
    ok "已安装，跳过: ${package}"
    return 0
  fi
  
  log "尝试安装工具包: ${package}"
  if install_packages "$package"; then
    ok "安装成功: ${package}"
    return 0
  fi
  if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
    if [[ "$APT_FIX_BROKEN_DONE" != "1" ]]; then
      warn "首次安装失败，尝试一次 APT 依赖修复后重试"
      run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y || true
      run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get install -f -y || true
      APT_FIX_BROKEN_DONE="1"
      if install_packages "$package"; then
        ok "修复依赖后安装成功: ${package}"
        return 0
      fi
    fi
  fi
  warn "安装失败，跳过: ${package}"
  return 1
}

configure_kali_ustc_source() {
  if [[ "$PACKAGE_MANAGER" != "apt" ]]; then
    warn "当前包管理器不是 apt，跳过 Kali 源配置"
    return 0
  fi
  if [[ "$AUTO_INSTALL" != "1" ]]; then
    warn "自动安装已禁用，跳过 Kali 源配置"
    return 0
  fi

  local keyring="/usr/share/keyrings/kali-archive-keyring.gpg"
  local source_line="deb [signed-by=${keyring}] https://mirrors.ustc.edu.cn/kali kali-rolling main contrib non-free non-free-firmware"

  install_packages gnupg ca-certificates || warn "安装 gnupg/ca-certificates 失败，后续源配置可能失败"
  if curl -fsSL https://archive.kali.org/archive-key.asc | run_with_privilege apt gpg --dearmor -o "$keyring"; then
    run_with_privilege apt chmod 0644 "$keyring" || true
  else
    warn "导入 Kali 仓库密钥失败，后续 apt update 可能失败"
  fi

  local source_file="/etc/apt/sources.list"
  if [[ "$DISTRO_ID" == "kali" ]]; then
    run_with_privilege apt cp "$source_file" "${source_file}.bak.$(date +%Y%m%d%H%M%S)" || true
    run_with_privilege apt sed -i 's/^[[:space:]]*deb[[:space:]].*kali/# &/g' "$source_file" || true
    if ! run_with_privilege apt grep -Fq "$source_line" "$source_file"; then
      printf '%s\n' "$source_line" | run_with_privilege apt tee -a "$source_file" >/dev/null
    fi
    ok "已将 Kali 源切换到中科大源"
  else
    local custom_list="/etc/apt/sources.list.d/kali-custom.list"
    if ! run_with_privilege apt grep -Fq "$source_line" "$custom_list" 2>/dev/null; then
      printf '%s\n' "$source_line" | run_with_privilege apt tee "$custom_list" >/dev/null
      # 设置较低优先级，防止 Kali 源破坏原生 Ubuntu/Debian 核心组件
      local pref_file="/etc/apt/preferences.d/kali-tools"
      cat <<EOF | run_with_privilege apt tee "$pref_file" >/dev/null
Package: *
Pin: release o=Kali
Pin-Priority: 150
EOF
      ok "已在非 Kali 系统中追加中科大 Kali 源 (低优先级防护模式)"
    else
      ok "中科大 Kali 源已存在于非 Kali 系统中"
    fi
  fi
  return 0
}

sanitize_non_kali_apt_state() {
  if [[ "$PACKAGE_MANAGER" != "apt" || "$DISTRO_ID" == "kali" ]]; then
    return 0
  fi
  
  warn "检测到非 Kali 系统，尝试深度清理可能引起严重冲突的 kali-defaults, seclists, feroxbuster..."
  
  # 1. 强制解除依赖死锁：使用 dpkg 强制卸载冲突包
  run_with_privilege apt dpkg --purge --force-all kali-defaults seclists feroxbuster >/dev/null 2>&1 || true
  
  # 2. 修复 APT 损坏状态
  run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y >/dev/null 2>&1 || true
  
  # 3. 再次标准卸载以清理残留
  run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get purge -y kali-defaults seclists feroxbuster >/dev/null 2>&1 || true
  run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1 || true
}

refresh_package_index_and_upgrade() {
  [[ "$AUTO_INSTALL" == "1" ]] || return 0
  case "$PACKAGE_MANAGER" in
    apt)
      run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get update -y || return 1
      if [[ "$DISTRO_ID" == "kali" ]]; then
        run_with_privilege apt env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || return 1
      fi
      PACKAGE_UPDATE_DONE="1"
      ;;
    dnf)
      run_with_privilege dnf dnf makecache || return 1
      run_with_privilege dnf dnf upgrade -y || return 1
      ;;
    yum)
      run_with_privilege yum yum makecache || return 1
      run_with_privilege yum yum update -y || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

install_security_toolchain() {
  [[ "$AUTO_INSTALL" == "1" ]] || return 0
  
  if [[ "$DISTRO_ID" == "kali" ]]; then
    ok "检测到 Kali 系统，跳过安全工具链安装"
    return 0
  fi

  local -a packages=()
  case "$PACKAGE_MANAGER" in
    apt)
      packages=(
        nmap masscan rustscan amass subfinder nuclei
        sqlmap hydra nikto gobuster dirsearch ffuf whatweb wafw00f whois
        exploitdb metasploit-framework john hashcat
        netcat-traditional socat proxychains4 chisel
        smbclient enum4linux
      )
      ;;
    dnf|yum)
      packages=(
        nmap masscan sqlmap hydra nikto gobuster ffuf whatweb whois
        metasploit john hashcat nmap-ncat socat proxychains-ng
        smbclient enum4linux
      )
      ;;
    *)
      warn "未支持的包管理器，跳过安全工具安装"
      return 0
      ;;
  esac

  local pkg
  for pkg in "${packages[@]}"; do
    install_package_best_effort "$pkg" || true
  done
}

ensure_exploit_tooling() {
  [[ "$AUTO_INSTALL" == "1" ]] || return 0
  [[ "$OS_FAMILY" == "linux" ]] || return 0

  if [[ "$DISTRO_ID" != "kali" ]]; then
    if ! has_cmd searchsploit; then
      install_package_best_effort exploitdb || true
    fi
    if ! has_cmd msfconsole; then
      install_package_best_effort metasploit-framework || true
    fi
  fi

  if has_cmd searchsploit; then
    ok "检测到 SearchSploit 离线检索能力"
  else
    warn "未检测到 searchsploit，离线 Exploit-DB 检索能力可能不可用"
  fi

  if has_cmd msfconsole; then
    ok "检测到 Metasploit Framework"
  else
    warn "未检测到 msfconsole，MSF 模块化利用能力可能不可用"
  fi

  local exploitdb_root="$ROOT_DIR/vuldb/exploit-db"
  local exploitdb_index="$exploitdb_root/files_exploits.csv"
  mkdir -p "$ROOT_DIR/vuldb"

  if [[ ! -f "$exploitdb_index" ]]; then
    if ! has_cmd git; then
      warn "未检测到 git，无法同步离线 Exploit-DB 仓库"
      return 0
    fi
    if [[ -d "$exploitdb_root/.git" ]]; then
      log "正在更新离线 Exploit-DB 仓库..."
      git -C "$exploitdb_root" pull --ff-only || warn "离线 Exploit-DB 仓库更新失败"
    else
      log "正在克隆离线 Exploit-DB 仓库..."
      git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$exploitdb_root" || warn "离线 Exploit-DB 仓库克隆失败"
    fi
  fi

  if [[ -f "$exploitdb_index" ]]; then
    ok "离线 Exploit-DB 漏洞库已就绪"
  else
    warn "离线 Exploit-DB 漏洞库尚未就绪，平台将无法执行本地漏洞脚本检索"
  fi
}

detect_platform

log "正在检查系统依赖项..."
ensure_system_command "$PYTHON_BIN" python
ensure_system_command pip3 python_pip
ensure_system_command curl curl
ensure_system_command git git
ensure_system_command unzip unzip
ensure_system_command tar tar
ensure_system_command gzip gzip
install_missing_system_dependencies

if ! has_cmd "$PYTHON_BIN"; then
  if has_cmd python3; then
    PYTHON_BIN="python3"
  elif has_cmd python; then
    PYTHON_BIN="python"
  else
    die "未找到 Python。请先安装 Python 3.10+。"
  fi
fi

PY_VERSION="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION##*.}"
if [[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10) ]]; then
  die "需要 Python 3.10+，当前版本: $PY_VERSION"
fi
ok "Python 版本检查通过: $PY_VERSION"
ensure_python_venv_support

if [[ ! -d "$VENV_DIR" ]]; then
  log "正在创建虚拟环境: $VENV_DIR"
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    die "创建虚拟环境失败，请先安装 venv 组件（Debian/Ubuntu 可执行: apt install python${PY_VERSION}-venv）"
  fi
fi

if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
  die "未找到虚拟环境激活脚本: $VENV_DIR/bin/activate"
fi

source "$VENV_DIR/bin/activate"
VENV_PYTHON="$(command -v python)"
log "工具执行模式: 系统 CLI（不依赖 tools/tools 本地目录）"
if [[ "$AUTO_INSTALL" == "1" ]]; then
  if [[ "$DISTRO_ID" == "kali" ]]; then
    ok "检测到原生 Kali Linux 系统，工具环境已完备，将仅更新系统"
    configure_kali_ustc_source || warn "Kali 源配置失败，将继续使用现有软件源"
    if ! refresh_package_index_and_upgrade; then
      warn "软件源更新或系统升级失败"
      [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且系统更新失败"
    fi
  else
    sanitize_non_kali_apt_state || warn "非Kali系统APT状态清理失败，继续执行"
    
    # 针对 Ubuntu 系统的特殊处理：官方推荐使用 Omnibus 安装包安装 MSF
    if [[ "$DISTRO_ID" == "ubuntu" ]]; then
      log "检测到 Ubuntu 系统，使用 Rapid7 官方 Omnibus 脚本安装 Metasploit Framework..."
      if ! has_cmd msfconsole; then
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall
        chmod +x /tmp/msfinstall
        # run_with_privilege 的第一个参数会被忽略（原设计用于包管理器名称），这里用 apt 占位
        run_with_privilege apt /tmp/msfinstall || warn "Metasploit 官方脚本安装失败"
        rm -f /tmp/msfinstall
      else
        ok "Ubuntu: MSF 已安装"
      fi
    fi

    configure_kali_ustc_source || warn "Kali 源配置失败，将继续使用现有软件源"
    if ! refresh_package_index_and_upgrade; then
      warn "软件源更新或系统升级失败"
      [[ "$STRICT_DEPS" == "1" ]] && die "STRICT_DEPS=1 且系统更新失败"
    fi
    install_security_toolchain
  fi
  ensure_exploit_tooling
else
  warn "已禁用自动安装，跳过 Kali 源与工具包安装流程"
fi

ensure_yak_on_path >/dev/null 2>&1 || true

if [[ "$BOOTSTRAP_ONLY" == "1" ]]; then
  ok "系统源配置与工具安装阶段已完成，按 WRAPT_BOOTSTRAP_ONLY=1 结束"
  exit 0
fi

if [[ "$AUTO_START_SERVICES" == "1" ]]; then
  log "正在启动辅助服务 (postgresql/msfdb) (若可用)..."

  if has_cmd systemctl && systemctl list-unit-files | grep -q '^postgresql.service'; then
    if is_root; then
      systemctl start postgresql || warn "启动 postgresql 失败"
    elif has_cmd sudo; then
      sudo systemctl start postgresql || warn "启动 postgresql 失败"
    else
      warn "未找到 sudo；无法启动 postgresql"
    fi
  fi

  if has_cmd msfdb; then
    msfdb start >/dev/null 2>&1 || warn "启动 msfdb 失败"
  fi
fi

if [[ "$SKIP_PIP_INSTALL" == "0" ]]; then
  if [[ ! -f "requirements.txt" ]]; then
    die "未找到 requirements.txt"
  fi

  log "正在安装 Python 依赖项 (使用清华源)..."
  python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
  python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

  if python -c "import playwright" >/dev/null 2>&1; then
    log "正在安装 Playwright Chromium 运行时..."
    PLAYWRIGHT_DOWNLOAD_HOST=https://registry.npmmirror.com/-/binary/playwright python -m playwright install chromium || python -m playwright install chromium || warn "Playwright 浏览器安装失败"
  fi
else
  warn "正在跳过 pip 依赖项安装"
fi

if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  die "${VENV_DIR} 中缺失 Python 包 fastapi/uvicorn。请不要使用 --skip-pip-install 运行。"
fi

log "正在确保运行时目录存在..."
mkdir -p output/reports output/exports output/sessions output/pocs logs knowledge skills mtools plugins fingerprints poc_exp/auto_generated tools/custom
ok "运行时目录已就绪"

check_ui_assets || exit 1

if [[ "$AI_WARMUP" == "1" ]]; then
  log "正在运行 Agent/RAG 预热检查..."
  if python -c "from core.api import routes; print('warmup-ok')" >/dev/null 2>&1; then
    ok "Agent/RAG 预热通过"
  else
    warn "Agent/RAG 预热失败；若相关功能不可用，请检查日志"
    if [[ "$STRICT_DEPS" == "1" ]]; then
      die "STRICT_DEPS=1 且 Agent/RAG 预热失败"
    fi
  fi
fi

resolve_service_identity
preserve_existing_service_admin_key

if [[ "$SERVICE_RUNTIME" == "1" ]]; then
  SERVICE_REGISTER="0"
fi

if [[ -n "$ADMIN_KEY" ]]; then
  export WRAPT_WEBUI_ACCESS_KEY="$ADMIN_KEY"
  ok "本次运行已启用 Admin key 认证"
fi

if [[ "$SERVICE_REGISTER" == "1" && "$HEALTH_CHECK" != "1" ]]; then
  warn "已禁用健康检查，无法满足服务化部署前置条件，自动跳过 systemd 服务注册"
  SERVICE_REGISTER="0"
fi

if [[ "$SERVICE_REGISTER" == "1" && ! systemd_is_available ]]; then
  err "当前环境缺少 systemd，无法完成服务化部署"
  print_service_recovery_path
  exit 1
fi

SERVER_CMD=(python -m uvicorn main:app --host "$HOST" --port "$PORT" --workers "$UVICORN_WORKERS")

if [[ "$SERVICE_RUNTIME" == "1" ]]; then
  log "检测到 systemd 托管模式，直接前台运行 Uvicorn"
  exec "${SERVER_CMD[@]}"
fi

if [[ "$SERVICE_REGISTER" == "1" && service_is_active && service_unit_exists ]]; then
  log "检测到 ${SERVICE_NAME}.service 已在运行，进入幂等更新流程"
  if health_check; then
    ok "当前 systemd 托管服务预检查通过"
  else
    warn "当前 systemd 托管服务预检查失败，将继续尝试重启修复"
  fi
  if reconcile_systemd_service; then
    exit 0
  fi
  exit 1
fi

log "正在启动服务器..."
log "访问地址: http://${HOST}:${PORT}"

if [[ "$HEALTH_CHECK" == "1" ]]; then
  "${SERVER_CMD[@]}" &
  SERVER_PID=$!

  cleanup() {
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  for attempt in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      wait "$SERVER_PID" || true
      die "服务器在通过健康检查前已退出"
    fi

    if health_check; then
      ok "健康检查通过 (API + UI 静态资源)"
      if [[ "$SERVICE_REGISTER" == "1" ]]; then
        cleanup
        wait "$SERVER_PID" || true
        trap - EXIT
        if reconcile_systemd_service; then
          exit 0
        fi
        exit 1
      fi
      wait "$SERVER_PID"
      exit $?
    fi

    log "正在等待服务器就绪... (${attempt}/30)"
    sleep 1
  done

  err "尝试 30 次后健康检查仍失败"
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  exit 1
else
  exec "${SERVER_CMD[@]}"
fi
