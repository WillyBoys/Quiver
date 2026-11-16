"""scripts/update_tools.py: pins in docker/executor.Dockerfile (offline parts)."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "update_tools.py"
spec = importlib.util.spec_from_file_location("update_tools", SCRIPT)
update_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_tools)

A, B = "a" * 64, "b" * 64


def dockerfile(**overrides):
    """A Dockerfile pinning every tool in the table, each checksum distinct."""
    args = {}
    for i, tool in enumerate(update_tools.TOOLS):
        args[f"{tool.upper()}_VERSION"] = "1.0.0"
        args[f"{tool.upper()}_SHA256_AMD64"] = f"{2 * i:064x}"
        args[f"{tool.upper()}_SHA256_ARM64"] = f"{2 * i + 1:064x}"
    args |= overrides
    return "FROM x\nARG TARGETARCH\n" + "".join(f"ARG {k}={v}\n" for k, v in args.items())


def test_committed_dockerfile_pins_every_tool():
    assert update_tools.check(update_tools.DOCKERFILE.read_text()) == []
    assert update_tools.main(["--check"]) == 0


@pytest.mark.parametrize(
    ("override", "problem"),
    [
        ({"DNSX_VERSION": "latest"}, "DNSX_VERSION"),
        ({"SUBFINDER_SHA256_ARM64": "abc"}, "SUBFINDER_SHA256_ARM64"),
        ({"SUBFINDER_SHA256_ARM64": f"{0:064x}"}, "same checksum"),  # = its AMD64 pin
    ],
)
def test_check_reports_bad_pins(override, problem):
    problems = update_tools.check(dockerfile(**override))
    assert len(problems) == 1 and problem in problems[0]


def test_check_reports_missing_pins():
    assert update_tools.check(dockerfile()) == []
    assert len(update_tools.check("FROM x\n")) == 3 * len(update_tools.TOOLS)


CHECKSUMS = f"""{A}  dnsx_1.3.2_linux_amd64.zip
{B}  dnsx_1.3.2_linux_arm64.zip
{"c" * 64}  dnsx_1.3.2_windows_amd64.zip
not a checksum line
"""


def test_checksums_for_reads_the_release_file():
    assert update_tools.checksums_for("dnsx", "1.3.2", CHECKSUMS) == {
        "SHA256_AMD64": A,
        "SHA256_ARM64": B,
    }
    with pytest.raises(ValueError, match="arm64"):
        update_tools.checksums_for("dnsx", "1.3.2", CHECKSUMS.replace("arm64", "armv6"))


def test_rewrite_replaces_only_that_tools_args():
    text = update_tools.rewrite(
        dockerfile(),
        "dnsx",
        {"VERSION": "1.3.2", "SHA256_AMD64": "c" * 64, "SHA256_ARM64": "d" * 64},
    )
    pins = update_tools.pins(text)
    assert pins["dnsx"] == {"VERSION": "1.3.2", "SHA256_AMD64": "c" * 64, "SHA256_ARM64": "d" * 64}
    assert pins["subfinder"] == update_tools.pins(dockerfile())["subfinder"]
    with pytest.raises(ValueError, match="exactly one"):
        update_tools.rewrite("FROM x\n", "dnsx", {"VERSION": "1.3.2"})
