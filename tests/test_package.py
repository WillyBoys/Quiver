import importlib

import pytest

import quiver


def test_version():
    assert quiver.__version__ == "0.1.0"


@pytest.mark.parametrize(
    "module",
    [
        "quiver.core",
        "quiver.api",
        "quiver.worker",
        "quiver.worker.tracks.external",
        "quiver.bridge",
    ],
)
def test_subpackages_import(module):
    importlib.import_module(module)
