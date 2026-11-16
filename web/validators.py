import re

LABEL_RE = re.compile(r"^[\w .\-()'@]{1,60}$", re.UNICODE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_label(value: str, field: str, max_len: int = 60) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} inválido.")
    if any(not ch.isprintable() for ch in value):
        raise ValueError(f"{field} contém caracteres de controle inválidos.")
    v = " ".join(value.split())[:max_len]
    if not v or not LABEL_RE.match(v):
        raise ValueError(f"{field} contém caracteres inválidos.")
    return v


def sanitize_existing_label(value: str, fallback: str = "Item", max_len: int = 60) -> str:
    """Best-effort cleanup for legacy DB rows that may contain control or invalid characters."""
    printable = "".join(ch for ch in (value or "") if ch.isprintable())
    collapsed = " ".join(printable.split())[:max_len]
    cleaned = re.sub(r"[^\w .\-()'@]", "", collapsed, flags=re.UNICODE).strip()
    return cleaned[:max_len] if cleaned else fallback


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Domínio inválido.")
    if any(not ch.isprintable() for ch in value):
        raise ValueError("Domínio inválido.")
    d = value.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].rstrip(".")
    if not d:
        raise ValueError("Domínio inválido.")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domínio inválido.") from exc
    if not DOMAIN_RE.match(d):
        raise ValueError("Domínio inválido.")
    return d


def clean_text(value: str, max_len: int) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in (value or "")).split())[:max_len]
