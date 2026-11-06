"""Third-party provider index: CNAME suffixes and address ranges, plus the bundled data."""

import ipaddress

import pytest

from quiver.core.policy.providers import ProviderIndex, bundled_providers
from quiver.core.policy.resolve import Resolution

INDEX = ProviderIndex(
    {
        "big": ["13.32.0.0/15", "2600:9000::/28"],
        "nested": ["13.33.10.0/24"],  # overlaps "big": either answer is a provider
        "small": ["198.51.100.0/24", "198.51.101.0/24"],  # adjacent: collapsed
    },
    {"big": ["cloudfront.net"], "saas": ["*.myshopify.com"]},
)


def ip(value):
    return ipaddress.ip_address(value)


@pytest.mark.parametrize(
    ("address", "provider"),
    [
        ("13.32.0.0", "big"),
        ("13.33.255.255", "big"),
        ("13.34.0.0", None),
        ("13.31.255.255", None),
        ("198.51.101.200", "small"),
        ("2600:9000::1", "big"),
        ("2600:9010::1", None),
        ("8.8.8.8", None),
    ],
)
def test_address_ranges(address, provider):
    assert INDEX.provider_of_address(ip(address)) == provider


def test_overlapping_ranges_are_found():
    assert INDEX.provider_of_address(ip("13.33.10.5")) in {"big", "nested"}


def test_range_after_a_wide_one_is_still_found():
    index = ProviderIndex({"wide": ["10.0.0.0/8"], "late": ["11.0.0.0/24"]}, {})
    assert index.provider_of_address(ip("11.0.0.1")) == "late"
    assert index.provider_of_address(ip("10.200.0.1")) == "wide"


@pytest.mark.parametrize(
    ("name", "provider"),
    [
        ("d111.cloudfront.net", "big"),
        ("cloudfront.net.", "big"),
        ("evilcloudfront.net", None),  # suffix match is on a label boundary
        ("store.myshopify.com", "saas"),
        ("example.com", None),
    ],
)
def test_cname_suffixes(name, provider):
    assert INDEX.provider_of_name(name) == provider


def test_classify_prefers_cname_evidence():
    res = Resolution("x.example.com", (ip("8.8.8.8"),), ("x.myshopify.com",))
    assert INDEX.classify(res) == "saas"
    assert INDEX.classify(Resolution("x.example.com", (ip("13.32.5.5"),))) == "big"
    assert INDEX.classify(Resolution("x.example.com", (ip("8.8.4.4"),))) is None


# --- bundled snapshot -----------------------------------------------------------------------


def test_bundled_data_loads_and_knows_the_big_providers():
    index = bundled_providers()
    assert index.generated_at
    assert index.provider_of_address(ip("104.16.0.1")) == "cloudflare"
    assert index.provider_of_address(ip("151.101.1.1")) == "fastly"
    assert index.provider_of_name("myapp.azurewebsites.net") == "azure"
    assert index.provider_of_name("d1234.cloudfront.net") == "aws"
    assert index.provider_of_name("someone.github.io") == "github"
    assert index.provider_of_address(ip("192.0.2.1")) is None  # documentation range
