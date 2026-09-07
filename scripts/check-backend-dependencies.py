"""Check installed backend distributions without importing models or using the network."""

import argparse
from importlib import metadata
from pathlib import Path


def check(requirements_path):
    try:
        from packaging.requirements import Requirement
    except ImportError:
        return ["packaging is not installed"]

    errors = []
    for line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        try:
            version = metadata.version(requirement.name)
        except metadata.PackageNotFoundError:
            errors.append(f"{requirement.name} is not installed")
            continue
        if version not in requirement.specifier:
            errors.append(f"{requirement.name} {version} does not satisfy {requirement.specifier}")
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    errors = check(Path(__file__).resolve().parents[1] / "backend" / "requirements.txt")
    if not args.quiet:
        print("\n".join(errors) if errors else "Backend dependency versions satisfy requirements.txt.")
    raise SystemExit(bool(errors))
