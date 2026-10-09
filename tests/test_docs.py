"""Docs and landing guards.

These pin the things that actually went wrong: a Russian phrase left inside the English README, a
"never auto-anything" construction nobody could parse, and the French copy drifting between
«constat» and «découverte» for the same glossary term.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

ROOT = Path(__file__).resolve().parents[1]
LANGS = ["en", "ru", "es", "fr", "zh"]
READMES = {
    "en": ROOT / "README.md",
    "ru": ROOT / "README.ru.md",
    "es": ROOT / "README.es.md",
    "fr": ROOT / "README.fr.md",
    "zh": ROOT / "README.zh.md",
}
LANDING = ROOT / "docs" / "landing" / "index.html"
HERO = ROOT / "docs" / "hero.svg"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- READMEs


@pytest.mark.parametrize("lang", LANGS)
def test_every_language_ships(lang):
    assert READMES[lang].is_file()


@pytest.mark.parametrize("lang", LANGS)
def test_each_readme_leads_with_the_hero_and_links_the_others(lang):
    text = _read(READMES[lang])
    assert 'src="docs/hero.svg"' in text
    for other in LANGS:
        if other == lang:
            continue
        assert READMES[other].name in text, other


@pytest.mark.parametrize("lang", LANGS)
def test_each_readme_carries_the_diagrams(lang):
    """Four mermaid blocks: isolation, the three outcomes, the pipeline, the fix cycle."""
    text = _read(READMES[lang])
    assert text.count("```mermaid") == 4
    assert "sequenceDiagram" in text and "flowchart" in text


@pytest.mark.parametrize("lang", LANGS)
def test_no_stray_russian_in_the_other_languages(lang):
    """A leftover «может фабрика это править» sat in the EN, ES and ZH READMEs for a release."""
    if lang == "ru":
        pytest.skip("Russian is expected here")
    # The language switcher legitimately says «Русский» — everything else must not be Cyrillic.
    body = [ln for ln in _read(READMES[lang]).splitlines() if "README.ru.md" not in ln]
    cyrillic = re.findall(r"[а-яА-ЯёЁ]{3,}", "\n".join(body))
    assert not cyrillic, cyrillic[:5]


@pytest.mark.parametrize("lang", LANGS)
def test_the_safety_boundary_is_stated_plainly(lang):
    """"never auto-anything" was unreadable in every language. The rule has to survive; the
    construction must not."""
    text = _read(READMES[lang]).lower()
    assert "auto-anything" not in text
    assert "auto-nada" not in text
    assert "авто-ничего" not in text
    assert "31337" in text
    assert "dolos_sandbox_chain_ids" in text


@pytest.mark.parametrize("lang", LANGS)
def test_the_exit_codes_are_documented(lang):
    text = _read(READMES[lang])
    assert "`2`" in text and "--only-exploits" in text


def test_french_uses_the_glossary_rendering_of_finding():
    """Glossary: FR `finding` is **constat**. «découverte» is the mesh discovery sense."""
    for path in (READMES["fr"], LANDING):
        text = _read(path)
        assert "constat" in text.lower(), path.name
        assert "découvert" not in text.lower(), path.name


# --------------------------------------------------------------------------- hero


def test_the_hero_is_an_svg_we_author_not_a_download():
    svg = _read(HERO)
    assert svg.lstrip().startswith("<svg")
    assert "<image" not in svg and "xlink:href" not in svg      # nothing embedded from elsewhere
    assert "THROWAWAY FORK" in svg and "LIVE CHAIN" in svg


# --------------------------------------------------------------------------- landing


def test_the_landing_mounts_the_procedural_scene():
    html = _read(LANDING)
    assert "./fork.js" in html
    assert '"three"' in html and "three/addons/" in html
    scene = _read(ROOT / "docs" / "landing" / "fork.js")
    assert "UnrealBloomPass" in scene and "OutputPass" in scene
    # the composer viewport must not be re-scaled by three's own pixel ratio
    assert "setPixelRatio(1)" in scene
    assert "prefers-reduced-motion" in scene


def test_the_landing_translations_have_identical_keys():
    """A missing key silently falls back to English mid-page, which reads as a broken translation."""
    html = _read(LANDING)
    block = re.search(r"const I18N = \{.*?\n\};", html, re.S)
    assert block, "I18N block not found"
    keys = {}
    for lang in LANGS:
        section = re.search(rf"\n  {lang}:\{{(.*?)\n(?:  \w+:\{{|\}};)", block.group(0), re.S)
        assert section, lang
        keys[lang] = set(re.findall(r"(?:^|,|\n)\s*(\w+):", section.group(1)))
    for lang in LANGS[1:]:
        assert keys[lang] == keys["en"], (lang, keys["en"] ^ keys[lang])


def test_the_landing_narrates_all_three_outcomes():
    """The scene's vocabulary is what the reader learns the product from; every language needs it."""
    html = _read(LANDING)
    for key in ("w_held", "w_exploited", "w_fix", "w_gone"):
        assert html.count(key + ":") == len(LANGS), key


@pytest.mark.skipif(not __import__("shutil").which("node"), reason="node not installed")
def test_the_landing_script_parses():
    """A stray quote in one translation takes the whole page down, silently."""
    html = _read(LANDING)
    block = re.search(r"const I18N = \{.*?\n\};", html, re.S).group(0)
    proc = subprocess.run([__import__("shutil").which("node"), "--input-type=module", "-e",
                           block + "\nif (Object.keys(I18N).length !== 5) throw new Error('langs');"],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_the_landing_points_at_the_sibling_layers():
    html = _read(LANDING)
    assert "basanos" in html.lower() and "momus" in html.lower()
    assert html.count("sib:") == len(LANGS)


def test_the_monitor_node_and_the_landing_agree_on_the_capability():
    for path in (LANDING, *READMES.values()):
        assert "agent.security.contract-redteam@v1" in _read(path), path.name
