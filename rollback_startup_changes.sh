#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="wrapt"
PORT="8000"
UNIT_NAME="${SERVICE_NAME}.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
ENV_PATH="/etc/default/${SERVICE_NAME}"

log() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok() { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

if [[ $# -gt 0 ]]; then
  err "本脚本不接收参数，直接执行即可。"
  exit 2
fi

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

run_as_root() {
  if is_root; then
    "$@"
  elif has_cmd sudo; then
    sudo "$@"
  else
    err "需要 root 权限，但系统未找到 sudo"
    return 1
  fi
}

systemd_available() {
  has_cmd systemctl && [[ -d /run/systemd/system ]]
}

service_known() {
  systemd_available || return 1
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$UNIT_NAME"
}

stop_disable_service() {
  if ! systemd_available; then
    warn "当前环境未检测到 systemd，跳过 systemd 停止流程"
    return 0
  fi

  if service_known || systemctl status "$UNIT_NAME" >/dev/null 2>&1; then
    log "正在停止并禁用 systemd 服务: $UNIT_NAME"
    run_as_root systemctl disable --now "$UNIT_NAME" || warn "停止或禁用失败，继续后续清理"
  else
    log "未发现已注册的 systemd 服务: $UNIT_NAME"
  fi
}

remove_service_files() {
  local removed="0"

  if run_as_root test -f "$UNIT_PATH"; then
    log "正在删除服务文件: $UNIT_PATH"
    run_as_root rm -f "$UNIT_PATH"
    removed="1"
  fi

  if run_as_root test -f "$ENV_PATH"; then
    log "正在删除环境文件: $ENV_PATH"
    run_as_root rm -f "$ENV_PATH"
    removed="1"
  fi

  if [[ "$removed" == "1" ]]; then
    ok "systemd 服务文件清理完成"
  else
    log "未发现需要删除的 systemd 文件"
  fi
}

reload_systemd_state() {
  if ! systemd_available; then
    return 0
  fi

  log "正在刷新 systemd 状态"
  run_as_root systemctl daemon-reload || warn "daemon-reload 失败"
  run_as_root systemctl reset-failed "$UNIT_NAME" || warn "reset-failed 失败"
}

collect_port_pids() {
  if ! has_cmd ss; then
    return 0
  fi

  ss -lntpH "( sport = :${PORT} )" 2>/dev/null \
    | grep -oE 'pid=[0-9]+' \
    | cut -d= -f2 \
    | sort -u || true
}

is_wrapt_related_pid() {
  local pid="$1"
  local cmdline
  cmdline="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [[ -n "$cmdline" ]] || return 1
  [[ "$cmdline" == *"$ROOT_DIR/start.sh"* ]] && return 0
  [[ "$cmdline" == *"uvicorn main:app"* ]] && return 0
  [[ "$cmdline" == *"$ROOT_DIR"* && "$cmdline" == *"python"* ]] && return 0
  return 1
}

kill_wrapt_port_processes() {
  local pid
  local found="0"

  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    found="1"
    if ! is_wrapt_related_pid "$pid"; then
      warn "端口 ${PORT} 上的 PID=${pid} 不是明显的 WRAPT 进程，已跳过"
      continue
    fi

    log "正在停止 WRAPT 常驻进程: PID=${pid}"
    run_as_root kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      warn "PID=${pid} 在 TERM 后仍存活，升级为 KILL"
      run_as_root kill -KILL "$pid" 2>/dev/null || true
    fi
  done < <(collect_port_pids)

  if [[ "$found" == "0" ]]; then
    log "端口 ${PORT} 上未发现需要清理的 WRAPT 进程"
  else
    ok "端口 ${PORT} 的 WRAPT 进程清理完成"
  fi
}

stop_helper_services() {
  if has_cmd systemctl && systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "postgresql.service"; then
    log "正在停止辅助服务: postgresql"
    run_as_root systemctl stop postgresql || warn "停止 postgresql 失败"
  fi

  if has_cmd msfdb; then
    log "正在停止辅助服务: msfdb"
    msfdb stop >/dev/null 2>&1 || warn "停止 msfdb 失败"
  fi
}

remove_project_runtime_artifacts() {
  local path
  local -a paths=(
    "$ROOT_DIR/.venv"
    "$ROOT_DIR/vuldb/exploit-db"
    "$ROOT_DIR/vuldb"
    "$ROOT_DIR/output/reports"
    "$ROOT_DIR/output/exports"
    "$ROOT_DIR/output/sessions"
    "$ROOT_DIR/output/pocs"
    "$ROOT_DIR/logs"
    "$ROOT_DIR/poc_exp/auto_generated"
    "$ROOT_DIR/tools/custom"
  )

  for path in "${paths[@]}"; do
    if [[ -e "$path" ]]; then
      log "正在删除运行时产物: $path"
      rm -rf "$path"
    fi
  done

  # 尽量恢复目录结构到回滚前，不删除仓库内原本存在的顶层目录，只清理空父目录。
  rmdir "$ROOT_DIR/output" 2>/dev/null || true
  rmdir "$ROOT_DIR/poc_exp" 2>/dev/null || true
  rmdir "$ROOT_DIR/tools" 2>/dev/null || true
}

restore_apt_source_changes() {
  local custom_list="/etc/apt/sources.list.d/kali-custom.list"
  local pref_file="/etc/apt/preferences.d/kali-tools"
  local source_file="/etc/apt/sources.list"
  local latest_backup=""

  if ! has_cmd apt-get; then
    return 0
  fi

  if run_as_root test -f "$custom_list"; then
    log "正在删除启动脚本追加的 Kali 源文件: $custom_list"
    run_as_root rm -f "$custom_list"
  fi

  if run_as_root test -f "$pref_file"; then
    log "正在删除启动脚本追加的 APT 优先级文件: $pref_file"
    run_as_root rm -f "$pref_file"
  fi

  if run_as_root test -f "$source_file"; then
    if run_as_root grep -q "mirrors\\.ustc\\.edu\\.cn/kali" "$source_file"; then
      latest_backup="$(run_as_root bash -lc "ls -1t /etc/apt/sources.list.bak.* 2>/dev/null | head -n 1" || true)"
      if [[ -n "$latest_backup" ]]; then
        log "正在恢复启动脚本修改前的 APT 源备份: $latest_backup"
        run_as_root cp "$latest_backup" "$source_file"
      else
        log "未找到备份文件，正在移除当前 sources.list 中的 Kali 中科大源"
        run_as_root sed -i '/mirrors\.ustc\.edu\.cn\/kali/d' "$source_file" || true
      fi
    fi
  fi

  log "正在刷新 APT 索引状态"
  run_as_root apt-get update -y >/dev/null 2>&1 || warn "apt-get update 失败，请手动检查软件源"
}

print_summary() {
  cat <<EOF

[完成] 已执行启动脚本强回滚：
  - 已停止并撤销 ${UNIT_NAME}
  - 已删除 ${UNIT_PATH} 与 ${ENV_PATH}
  - 已清理端口 ${PORT} 的 WRAPT 常驻进程
  - 已停止 postgresql / msfdb（若存在）
  - 已删除 .venv、离线 Exploit-DB 与运行时目录
  - 已回滚启动脚本追加的 Kali APT 源与优先级文件

说明:
  - 本脚本已尽量回滚启动脚本可可靠判定的落盘与服务侧改动。
  - 系统级软件包升级/安装无法可靠区分“原本就存在”与“启动脚本新增”，因此未做自动卸载，避免误伤系统。
EOF
}

main() {
  log "开始执行启动脚本强回滚"
  stop_disable_service
  remove_service_files
  reload_systemd_state
  kill_wrapt_port_processes
  stop_helper_services
  remove_project_runtime_artifacts
  restore_apt_source_changes
  print_summary
}

main
