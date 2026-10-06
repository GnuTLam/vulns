from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def manifest_lines(name: str) -> list[str]:
    return [
        line.strip()
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_production_dependencies_exclude_test_tooling():
    runtime = manifest_lines("requirements.txt")
    development = manifest_lines("requirements-dev.txt")

    assert not any(line.startswith(("pytest==", "httpx==", "ruff==")) for line in runtime)
    assert "-r requirements.txt" in development
    assert any(line.startswith("pytest==") for line in development)


def test_docker_context_only_ships_the_application():
    ignored = manifest_lines(".dockerignore")

    assert ignored[0] == "*"
    assert {line for line in ignored if line.startswith("!")} == {"!app/", "!requirements.txt"}

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY requirements.txt ./" in dockerfile
    assert "requirements-dev.txt" not in dockerfile
    assert "COPY app ./app" in dockerfile
