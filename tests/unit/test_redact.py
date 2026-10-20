import json

from injectkit.redact import Redactor, strip_control

HIDDEN = "s3cr3t-Value/with+chars"


def test_masks_plain_secret() -> None:
    r = Redactor()
    r.add(HIDDEN)
    assert HIDDEN not in r.mask(f"token={HIDDEN}!")


def test_empty_values_are_ignored() -> None:
    r = Redactor()
    r.add("")
    assert r.mask("nothing to hide") == "nothing to hide"


def test_labelled_secret_uses_label() -> None:
    r = Redactor()
    r.add(HIDDEN, label="sys-1")
    assert r.mask(f"leak {HIDDEN}") == "leak [REDACTED:sys-1]"


def test_masks_url_quoted_variants() -> None:
    from urllib.parse import quote, quote_plus

    r = Redactor()
    r.add(HIDDEN)
    masked = r.mask(f"GET /x?k={quote(HIDDEN, safe='')}&p={quote_plus(HIDDEN)}")
    assert quote(HIDDEN, safe="") not in masked
    assert quote_plus(HIDDEN) not in masked


def test_masks_json_escaped_variant() -> None:
    r = Redactor()
    r.add('he said "hi"\nbye')
    serialized = json.dumps({"msg": 'he said "hi"\nbye'})
    masked = r.mask(serialized)
    assert "hi" not in masked


def test_masks_exception_text_and_keeps_type() -> None:
    r = Redactor()
    r.add(HIDDEN)
    text = r.mask_exception(ValueError(f"bad header {HIDDEN}"))
    assert HIDDEN not in text
    assert text.startswith("ValueError: ")


def test_masks_nested_json_structures() -> None:
    r = Redactor()
    r.add(HIDDEN)
    data = {"a": [{"b": f"x {HIDDEN} y"}], "n": 3, "ok": True}
    masked = r.mask_json(data)
    assert HIDDEN not in json.dumps(masked)
    assert masked["n"] == 3
    assert data["a"][0]["b"].count(HIDDEN) == 1  # input is not mutated


def test_overlapping_secrets_longest_first() -> None:
    r = Redactor()
    r.add("abcdef")
    r.add("abcdefghij")
    assert r.mask("xx abcdefghij yy") == "xx [REDACTED] yy"


def test_mask_is_noop_without_secrets() -> None:
    assert Redactor().mask("plain") == "plain"


def test_strip_control_removes_ansi_and_control_chars() -> None:
    dirty = "ok\x1b[31mred\x1b[0m\x07bell\x1b]0;title\x07done\x00\x7f\u009b"
    assert strip_control(dirty) == "okredbelldone"


def test_strip_control_keeps_newline_and_tab() -> None:
    assert strip_control("a\tb\nc") == "a\tb\nc"


def test_masks_base64_and_lowercase_percent_encoding() -> None:
    import base64

    r = Redactor()
    r.add(HIDDEN)
    b64 = base64.b64encode(HIDDEN.encode()).decode()
    lower_pct = "s3cr3t-Value%2fwith%2bchars"
    masked = r.mask(f"{b64} {lower_pct}")
    assert b64 not in masked
    assert lower_pct not in masked


def test_strip_control_removes_bidi_and_zero_width() -> None:
    assert strip_control("a\u202eb\u200bc\u2066d\ufeffe") == "abcde"


def test_strip_control_removes_invisible_smuggling_characters() -> None:
    hidden = "\u2028\u2029\u2060\u2064\u061c\u180e\ufff9\ufffb" + "".join(
        chr(0xE0000 + i) for i in (1, 0x41, 0x7F)
    )
    assert strip_control(f"a{hidden}b") == "ab"


def test_strip_control_keeps_newline_tab_and_ordinary_unicode() -> None:
    assert strip_control("a\tb\nc \u00e9\u4e2d") == "a\tb\nc \u00e9\u4e2d"
