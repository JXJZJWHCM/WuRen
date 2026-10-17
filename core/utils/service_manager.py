import argparse
import json
import os
import re
import shlex
import textwrap
from dataclasses import dataclass
from typing import Dict, List


_SAFE_SERVICE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]+$")


def _shell_quote(value: str) -> str:
    return shlex.quote(str(value))


def _systemd_escape(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def normalize_service_name(service_name: str) -> str:
    normalized = (service_name or "").strip()
    if not normalized:
        raise ValueError("service_name 不能为空")
    if normalized.endswith(".service"):
        normalized = normalized[:-8]
    if not _SAFE_SERVICE_NAME_PATTERN.fullmatch(normalized):
        raise ValueError("service_name 仅允许字母、数字、点、下划线、短横线与 @")
    return normalized


@dataclass(frozen=True)
class SystemdServiceSpec:
    service_name: str
    root_dir: str
    script_path: str
    unit_path: str
    env_path: str
    host: str
    port: int
    workers: int
    venv_dir: str
    python_bin: str
    service_user: str
    service_group: str
    description: str = "WRAPT Web Service"
    admin_key: str = ""
    allow_non_kali: bool = False
    auto_start_services: bool = True

    @property
    def unit_name(self) -> str:
        return f"{self.service_name}.service"


def build_exec_start(spec: SystemdServiceSpec) -> str:
    args = [
        "/usr/bin/env",
        "bash",
        spec.script_path,
        "--service-runtime",
        "--host",
        spec.host,
        "--port",
        str(spec.port),
        "--workers",
        str(spec.workers),
        "--venv",
        spec.venv_dir,
        "--python",
        spec.python_bin,
    ]
    if spec.allow_non_kali:
        args.append("--allow-non-kali")
    if not spec.auto_start_services:
        args.append("--no-auto-services")
    return " ".join(_shell_quote(item) for item in args)


def render_environment_file(spec: SystemdServiceSpec) -> str:
    header = [
        "# 由 core.utils.service_manager 自动生成",
        "# 如需持久化管理密钥，请修改后重新执行 start.sh",
    ]
    if spec.admin_key:
        header.append(f"WRAPT_WEBUI_ACCESS_KEY={_systemd_escape(spec.admin_key)}")
    return "\n".join(header) + "\n"


def render_systemd_unit(spec: SystemdServiceSpec) -> str:
    unit = f"""
    [Unit]
    Description={spec.description}
    Wants=network-online.target
    After=network-online.target

    [Service]
    Type=simple
    User={spec.service_user}
    Group={spec.service_group}
    WorkingDirectory={spec.root_dir}
    Environment=PYTHONUNBUFFERED=1
    Environment=WRAPT_SERVICE_MANAGED=1
    EnvironmentFile=-{spec.env_path}
    ExecStart={build_exec_start(spec)}
    Restart=on-failure
    RestartSec=5s
    TimeoutStopSec=30s
    KillSignal=SIGINT
    LimitNOFILE=65535

    [Install]
    WantedBy=multi-user.target
    """
    return textwrap.dedent(unit).strip() + "\n"


def write_text_if_changed(path: str, content: str) -> bool:
    existing = None
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as file:
            existing = file.read()
    if existing == content:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        file.write(content)
    return True


def build_recovery_commands(spec: SystemdServiceSpec) -> List[str]:
    unit_name = spec.unit_name
    return [
        f"sudo systemctl status {unit_name} --no-pager -l",
        f"sudo journalctl -u {unit_name} -n 200 --no-pager",
        f"sudo systemctl disable --now {unit_name}",
        f"sudo rm -f {_shell_quote(spec.unit_path)} {_shell_quote(spec.env_path)}",
        "sudo systemctl daemon-reload",
        f"sudo systemctl reset-failed {unit_name}",
    ]


def materialize_service_files(spec: SystemdServiceSpec) -> Dict[str, object]:
    unit_changed = write_text_if_changed(spec.unit_path, render_systemd_unit(spec))
    env_changed = write_text_if_changed(spec.env_path, render_environment_file(spec))
    return {
        "service_name": spec.service_name,
        "unit_name": spec.unit_name,
        "unit_path": spec.unit_path,
        "env_path": spec.env_path,
        "unit_changed": unit_changed,
        "env_changed": env_changed,
        "recovery_commands": build_recovery_commands(spec),
    }


def _build_spec_from_args(args: argparse.Namespace) -> SystemdServiceSpec:
    service_name = normalize_service_name(args.service_name)
    return SystemdServiceSpec(
        service_name=service_name,
        root_dir=os.path.abspath(args.root_dir),
        script_path=os.path.abspath(args.script_path),
        unit_path=os.path.abspath(args.unit_path),
        env_path=os.path.abspath(args.env_path),
        host=args.host,
        port=int(args.port),
        workers=int(args.workers),
        venv_dir=args.venv_dir,
        python_bin=args.python_bin,
        service_user=args.service_user,
        service_group=args.service_group,
        description=args.description,
        admin_key=args.admin_key or "",
        allow_non_kali=bool(args.allow_non_kali),
        auto_start_services=not bool(args.no_auto_services),
    )


def _create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WRAPT systemd 服务文件生成器")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_arguments(target: argparse.ArgumentParser) -> None:
        target.add_argument("--service-name", required=True)
        target.add_argument("--root-dir", required=True)
        target.add_argument("--script-path", required=True)
        target.add_argument("--unit-path", required=True)
        target.add_argument("--env-path", required=True)
        target.add_argument("--host", required=True)
        target.add_argument("--port", required=True, type=int)
        target.add_argument("--workers", required=True, type=int)
        target.add_argument("--venv-dir", required=True)
        target.add_argument("--python-bin", required=True)
        target.add_argument("--service-user", required=True)
        target.add_argument("--service-group", required=True)
        target.add_argument("--description", default="WRAPT Web Service")
        target.add_argument("--admin-key", default="")
        target.add_argument("--allow-non-kali", action="store_true")
        target.add_argument("--no-auto-services", action="store_true")

    materialize_parser = subparsers.add_parser("materialize", help="写入/更新 systemd 资源文件")
    add_common_arguments(materialize_parser)

    recovery_parser = subparsers.add_parser("recovery", help="输出恢复命令")
    add_common_arguments(recovery_parser)
    return parser


def main() -> int:
    parser = _create_argument_parser()
    args = parser.parse_args()
    spec = _build_spec_from_args(args)

    if args.command == "materialize":
        print(json.dumps(materialize_service_files(spec), ensure_ascii=False))
        return 0
    if args.command == "recovery":
        print(json.dumps({"recovery_commands": build_recovery_commands(spec)}, ensure_ascii=False))
        return 0
    parser.error(f"不支持的命令: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
