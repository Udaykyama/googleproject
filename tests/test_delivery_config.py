"""Digest-only production deployment command validation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "deploy" / "production-compose"
VALID_IMAGE = (
    "ghcr.io/udaykyama/googleproject@sha256:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def _fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
[ "${APP_IMAGE+x}" != "x" ]
[ "${APP_DATA_DIR+x}" != "x" ]
[ "${BACKUP_DIR+x}" != "x" ]
[ "${SECRET_KEY+x}" != "x" ]
[ "${COMPOSE_FILE+x}" != "x" ]
[ "${COMPOSE_PROJECT_NAME+x}" != "x" ]
command=$1
shift
if [ "$command" = "compose" ]; then
  [ "$1" = "--project-name" ]
  [ "$2" = "inboxready" ]
  shift 2
  [ "$1" = "--file" ]
  case "$2" in
    */compose.yaml) ;;
    *) exit 65 ;;
  esac
  shift 2
  [ "$1" = "--env-file" ]
  shift 2
  case "$*" in
    "config --images")
      printf '%s\\n' "$FAKE_IMAGE"
      ;;
    "config --quiet" | \\
    "pull --policy always app" | \\
    "up -d --no-build --pull never --wait app")
      ;;
    *)
      echo "unexpected fake compose invocation: $*" >&2
      exit 64
      ;;
  esac
elif [ "$command" = "image" ] && [ "$1" = "inspect" ]; then
    printf '%s\\n' "$FAKE_IMAGE"
else
  echo "unexpected fake docker invocation: $command $*" >&2
  exit 64
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return bin_dir, log


def _run(tmp_path: Path, image: str, action: str = "config"):
    bin_dir, log = _fake_docker(tmp_path)
    env_file = tmp_path / "app.env"
    env_file.write_text("placeholder-only-for-fake-docker=true\n", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_DOCKER_LOG": str(log),
        "FAKE_IMAGE": image,
        "COMPOSE_FILE": str(tmp_path / "untrusted-compose.yaml"),
        "COMPOSE_PROJECT_NAME": "untrusted-project",
        "APP_IMAGE": "ghcr.io/udaykyama/googleproject:mutable",
        "APP_DATA_DIR": "/tmp/untrusted-data",
        "BACKUP_DIR": "/tmp/untrusted-backups",
        "SECRET_KEY": "untrusted-exported-secret",
    }
    result = subprocess.run(
        [str(COMMAND), "--env-file", str(env_file), action],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def test_production_config_rejects_mutable_or_wrong_repository_images(tmp_path):
    for image in (
        "ghcr.io/udaykyama/googleproject:v1.0.0",
        VALID_IMAGE.replace("googleproject", "other"),
        f"{VALID_IMAGE}\n{VALID_IMAGE}",
    ):
        result, calls = _run(tmp_path / str(len(image)), image)
        assert result.returncode == 1
        assert "APP_IMAGE must be" in result.stderr or "exactly one" in result.stderr
        assert not any(" pull " in call or " up " in call for call in calls)


def test_production_deploy_pulls_and_starts_only_the_approved_digest(tmp_path):
    result, calls = _run(tmp_path, VALID_IMAGE, "deploy")

    assert result.returncode == 0, result.stderr
    assert f"approved image: {VALID_IMAGE}" in result.stdout
    assert "--project-name inboxready --file " in calls[0]
    assert "/compose.yaml --env-file " in calls[0]
    assert calls[0].endswith("config --quiet")
    assert calls[1].endswith("config --images")
    assert calls[2].endswith("pull --policy always app")
    assert calls[3].startswith("image inspect --format ")
    assert calls[3].endswith(f" {VALID_IMAGE}")
    assert calls[4].endswith("up -d --no-build --pull never --wait app")


def test_production_command_fails_before_docker_for_missing_env_file(tmp_path):
    result = subprocess.run(
        [str(COMMAND), "--env-file", str(tmp_path / "missing.env"), "deploy"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "environment file is not readable" in result.stderr


@pytest.mark.parametrize(
    "unit_name",
    [
        "inboxready-backup.service",
        "inboxready-operational-check.service",
    ],
)
def test_systemd_operations_pin_compose_and_clear_environment(unit_name):
    unit = (ROOT / "deploy" / "systemd" / unit_name).read_text(encoding="utf-8")

    assert "UnsetEnvironment=APP_IMAGE APP_DATA_DIR BACKUP_DIR SECRET_KEY" in unit
    assert "--project-name inboxready --file /opt/inboxready/compose.yaml" in unit
    assert "--env-file /etc/inboxready/app.env" in unit
