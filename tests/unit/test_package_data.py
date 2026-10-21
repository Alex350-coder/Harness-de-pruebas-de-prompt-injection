"""Build the real wheel and sdist once and inspect them (needs the ``uv`` executable)."""

import shutil
import subprocess
import tarfile
import zipfile
from collections.abc import Iterator
from email.parser import Parser
from pathlib import Path

import pytest

import injectkit

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SUITES = {"basic", "quick"}
EXPECTED_LIBRARY = 8


@pytest.fixture(scope="module")
def dist(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    uv = shutil.which("uv")
    assert uv is not None, "the uv executable is required to build the package"
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(  # noqa: S603 - fixed argv, trusted executable
        [uv, "build", "--out-dir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
        timeout=300,
    )
    yield out


def wheel_names(dist: Path) -> list[str]:
    (wheel,) = dist.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        return archive.namelist()


def sdist_names(dist: Path) -> list[str]:
    (sdist,) = dist.glob("*.tar.gz")
    with tarfile.open(sdist) as archive:
        return archive.getnames()


def test_wheel_contains_typing_marker_and_all_payload_data(dist: Path) -> None:
    names = wheel_names(dist)
    assert "injectkit/py.typed" in names
    for suite in EXPECTED_SUITES:
        assert f"injectkit/payloads/data/suites/{suite}.yaml" in names
    library = [n for n in names if n.startswith("injectkit/payloads/data/suites/library/")]
    assert len([n for n in library if n.endswith(".yaml")]) == EXPECTED_LIBRARY


def test_wheel_ships_no_tooling_state_tests_or_planning_files(dist: Path) -> None:
    for name in wheel_names(dist):
        assert not name.startswith(("tests", "Planning_files", "docs")), name
        assert ".claude" not in name, name
        assert "__pycache__" not in name, name
        assert not name.endswith((".pyc", ".env", ".sarif", ".coverage")), name


def test_sdist_excludes_planning_tests_and_tooling_state(dist: Path) -> None:
    for name in sdist_names(dist):
        relative = name.split("/", 1)[1] if "/" in name else ""
        assert not relative.startswith(("tests", "Planning_files", ".github", ".venv")), name
        assert ".claude" not in name, name
        assert "__pycache__" not in name, name
        assert not relative.startswith(".env"), name


def test_sdist_still_has_sources_license_and_readme(dist: Path) -> None:
    names = {n.split("/", 1)[1] for n in sdist_names(dist) if "/" in n}
    assert {"LICENSE", "README.md", "pyproject.toml", "src/injectkit/py.typed"} <= names


def test_entry_points_are_declared(dist: Path) -> None:
    (wheel,) = dist.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        (entry,) = [n for n in archive.namelist() if n.endswith("entry_points.txt")]
        text = archive.read(entry).decode("utf-8")
    assert "injectkit = injectkit.cli:app" in text
    assert "injectkit-demo = injectkit.demo.cli:main" in text


def test_metadata_is_complete_and_the_version_is_single_sourced(dist: Path) -> None:
    (wheel,) = dist.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        (meta_name,) = [n for n in archive.namelist() if n.endswith("METADATA")]
        meta = Parser().parsestr(archive.read(meta_name).decode("utf-8"))
    assert meta["Name"] == "injectkit"
    assert meta["Version"] == injectkit.__version__
    assert meta["License-Expression"] == "Apache-2.0"
    assert meta["Requires-Python"] == ">=3.12"
    classifiers = meta.get_all("Classifier") or []
    assert "Typing :: Typed" in classifiers
    assert "Topic :: Security" in classifiers
    assert "TODO-USER" not in str(meta)


def test_declared_version_is_not_duplicated_in_source() -> None:
    source = (ROOT / "src" / "injectkit" / "__init__.py").read_text(encoding="utf-8")
    assert "importlib.metadata" in source
    assert "0.1.0" not in source
