from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.state = root / "state"
        self.state.mkdir()
        bindir = root / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -eu
                printf '%s\\n' "$*" >> "$FAKE_DOCKER_STATE/commands"

                case "${1:-}" in
                  info)
                    if [[ "${2:-}" == "--format" ]]; then
                      printf 'amd64\\n'
                    fi
                    ;;
                  pull|start|stop)
                    ;;
                  exec)
                    [[ "${FAKE_DOCKER_FAIL_EXEC:-0}" != "1" ]]
                    ;;
                  run)
                    touch "$FAKE_DOCKER_STATE/container"
                    ;;
                  inspect)
                    if [[ "${2:-}" == "--format" ]]; then
                      printf '%s\\n' "${FAKE_DOCKER_MANAGED:-true}"
                    fi
                    ;;
                  container)
                    [[ "${2:-}" == "inspect" ]]
                    test -f "$FAKE_DOCKER_STATE/container"
                    ;;
                  rename)
                    mv "$FAKE_DOCKER_STATE/container" "$FAKE_DOCKER_STATE/${3}"
                    ;;
                  rm)
                    target="${@: -1}"
                    rm -f "$FAKE_DOCKER_STATE/${target}" "$FAKE_DOCKER_STATE/container"
                    ;;
                  volume)
                    case "${2:-}" in
                      inspect)
                        if [[ "${3:-}" == "--format" ]]; then
                          test -f "$FAKE_DOCKER_STATE/volume"
                          printf 'true\\n'
                        else
                          test -f "$FAKE_DOCKER_STATE/volume"
                        fi
                        ;;
                      create)
                        touch "$FAKE_DOCKER_STATE/volume"
                        printf 'drost-ai-workspace\\n'
                        ;;
                      rm)
                        rm -f "$FAKE_DOCKER_STATE/volume"
                        ;;
                    esac
                    ;;
                  *)
                    printf 'unexpected docker invocation: %s\\n' "$*" >&2
                    exit 2
                    ;;
                esac
                """
            )
        )
        docker.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "FAKE_DOCKER_STATE": str(self.state),
        }

    def run_installer(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(INSTALLER), *arguments],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def commands(self) -> str:
        return (self.state / "commands").read_text()

    def test_fresh_install_pulls_versioned_image_and_self_tests(self) -> None:
        result = self.run_installer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Drost Community Edition 1.0.0 is ready", result.stdout)
        calls = self.commands()
        self.assertIn("pull ghcr.io/drost-ai/drost-community:1.0.0", calls)
        self.assertIn("volume create --label com.drost.community.managed=true drost-ai-workspace", calls)
        self.assertIn("--label com.drost.community.managed=true", calls)
        self.assertIn("exec drost-ai drost-mcp --self-test", calls)

    def test_repeat_install_replaces_only_managed_container(self) -> None:
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)

        second = self.run_installer()

        self.assertEqual(second.returncode, 0, second.stderr)
        calls = self.commands()
        self.assertIn("stop drost-ai", calls)
        self.assertIn("rename drost-ai drost-ai-rollback-", calls)
        self.assertNotIn("volume rm", calls)

    def test_existing_unmanaged_container_is_not_replaced(self) -> None:
        (self.state / "container").touch()
        self.env["FAKE_DOCKER_MANAGED"] = "false"

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not managed by this installer", result.stderr)
        calls = self.commands()
        self.assertNotIn("stop drost-ai", calls)
        self.assertNotIn("rename drost-ai", calls)

    def test_uninstall_preserves_workspace_unless_purge_is_explicit(self) -> None:
        installed = self.run_installer()
        self.assertEqual(installed.returncode, 0, installed.stderr)

        removed = self.run_installer("--uninstall")

        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertTrue((self.state / "volume").exists())
        self.assertIn("preserved workspace volume", removed.stdout)

    def test_explicit_purge_removes_managed_workspace(self) -> None:
        installed = self.run_installer()
        self.assertEqual(installed.returncode, 0, installed.stderr)

        removed = self.run_installer("--uninstall", "--purge-workspace")

        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.state / "volume").exists())
        self.assertIn("volume rm drost-ai-workspace", self.commands())

    def test_purge_without_uninstall_is_rejected(self) -> None:
        result = self.run_installer("--purge-workspace")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("may only be used with --uninstall", result.stderr)


if __name__ == "__main__":
    unittest.main()
