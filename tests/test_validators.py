import pytest
from validators import clean_label, normalize_domain, clean_text


@pytest.mark.parametrize(
    "bad_name",
    [
        "X\nAllowedIPs = 0.0.0.0/0",
        "Meu\nCelular",
        "Nome\r\nOutro",
        "[Interface]",
        "PostUp=id",
        "Nome;rm -rf /",
        "   ",
        "",
        "a\x00b",
    ],
)
def test_clean_label_rejects_injection_and_control_chars(bad_name):
    with pytest.raises(ValueError):
        clean_label(bad_name, "Nome")


def test_clean_label_accepts_valid_names_and_truncates():
    assert clean_label("  João   Silva (Casa)  ", "Nome") == "João Silva (Casa)"
    assert clean_label("Celular - Maria's @home_1", "Dispositivo") == "Celular - Maria's @home_1"
    long_name = "A" * 80
    assert len(clean_label(long_name, "Nome")) == 60


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("  HTTP://Site.COM/caminho?a=1 ", "site.com"),
        ("https://sub.domain.com.br:8443/login", "sub.domain.com.br"),
        ("example.com.", "example.com"),
        ("ação.com.br", "xn--ao-siap.com.br"),
    ],
)
def test_normalize_domain_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "bad_domain",
    [
        "a.com\nserver=8.8.8.8",
        "a.com\r\ndhcp-script=/bin/sh",
        "semtld",
        "site com espaco.com",
        "-invalido.com",
        "a.123",
        "",
        "   ",
    ],
)
def test_normalize_domain_rejects_invalid(bad_domain):
    with pytest.raises(ValueError):
        normalize_domain(bad_domain)


def test_clean_text_strips_newlines_and_limits_length():
    assert clean_text("Linha 1\nLinha 2\t\r", 50) == "Linha 1 Linha 2"
    assert len(clean_text("x" * 100, 20)) == 20
