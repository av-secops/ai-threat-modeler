import importlib.util
from pathlib import Path


def load_checker():
    path = Path(__file__).resolve().parents[2] / "scripts" / "check-backend-dependencies.py"
    spec = importlib.util.spec_from_file_location("check_backend_dependencies", path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


def test_dependency_checker_accepts_installed_version_and_skips_false_markers(tmp_path, monkeypatch):
    checker = load_checker()
    requirements = tmp_path / "requirements.txt"
    requirements.write_text('# Header\nexample[extra]>=1,<2\nabsent; python_version < "2"\n', encoding="utf-8")
    monkeypatch.setattr(checker.metadata, "version", lambda name: "1.5")
    assert checker.check(requirements) == []


def test_dependency_checker_reports_missing_and_incompatible_versions(tmp_path, monkeypatch):
    checker = load_checker()
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("missing>=1\nexample>=2,<3\n", encoding="utf-8")

    def version(name):
        if name == "missing":
            raise checker.metadata.PackageNotFoundError(name)
        return "1.5"

    monkeypatch.setattr(checker.metadata, "version", version)
    errors = checker.check(requirements)
    assert errors[0] == "missing is not installed"
    assert "does not satisfy" in errors[1]
