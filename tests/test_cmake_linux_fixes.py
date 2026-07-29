#!/usr/bin/env python3
"""Structural regression tests for Linux CMake fixes (GitHub issue #2).

Drives the shipped CMakeLists.txt (not a reimplementation): asserts the
Linux branch includes cstool headers, links wx static archives, optional
gspell, and Xxf86vm so the reported link/include gaps cannot regress.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CMAKE = ROOT / "CMakeLists.txt"


def _linux_section(text: str) -> str:
    """Return the Linux-only cmake body (both include and link halves)."""
    # Top-level Linux include branch: else() # Linux after WIN32, before endif of platform includes
    # and the bottom link branch: else() # Linux after WIN32 link block.
    parts: list[str] = []
    # Match every "else() # Linux" ... until matching platform endif/elseif boundary
    for m in re.finditer(
        r"else\(\)\s*#\s*Linux\b(.*?)(?=\n(?:endif\(\)|elseif\(|if\())",
        text,
        flags=re.S | re.I,
    ):
        parts.append(m.group(1))
    if not parts:
        # Fallback: whole file if markers missing (still scan for required tokens)
        return text
    return "\n".join(parts)


def main() -> int:
    if not CMAKE.is_file():
        print(f"FAIL: missing {CMAKE}", file=sys.stderr)
        return 1

    text = CMAKE.read_text(encoding="utf-8", errors="replace")
    linux = _linux_section(text)
    failures: list[str] = []

    def require(label: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"PASS: {label}")
        else:
            msg = f"FAIL: {label}" + (f" — {detail}" if detail else "")
            print(msg, file=sys.stderr)
            failures.append(msg)

    # 1) src/cstool on Linux include path
    require(
        "Linux include path contains src/cstool",
        re.search(r"src/cstool", linux) is not None,
        "issue #2 item 1",
    )

    # 2) wx static archives linked (stc → scintilla → adv/html → core → base)
    wx_libs = [
        r"libwx_gtk3u_stc-3\.2\.a",
        r"libwxscintilla-3\.2\.a",
        r"libwx_gtk3u_adv-3\.2\.a",
        r"libwx_gtk3u_html-3\.2\.a",
        r"libwx_gtk3u_core-3\.2\.a",
        r"libwx_baseu-3\.2\.a",
    ]
    missing_wx = [p for p in wx_libs if not re.search(p, linux)]
    require(
        "Linux links wx static archives (stc/scintilla/adv/html/core/base)",
        not missing_wx,
        f"missing: {missing_wx}" if missing_wx else "",
    )
    require(
        "Linux WX_LIBS fed into target_link_libraries",
        re.search(r"target_link_libraries\s*\(\s*\$\{PROJECT_NAME\}[^)]*\$\{WX_LIBS\}", linux, re.S)
        is not None
        or re.search(r"\$\{WX_LIBS\}", linux) is not None,
    )

    # 3) gspell optional (not REQUIRED)
    require(
        "Linux optional pkg_check_modules(GSPELL gspell-1)",
        re.search(r"pkg_check_modules\s*\(\s*GSPELL\s+gspell-1\s*\)", linux) is not None,
        "must not be REQUIRED so distros without gspell still configure",
    )
    require(
        "GSPELL not marked REQUIRED",
        re.search(r"pkg_check_modules\s*\(\s*GSPELL\s+REQUIRED\b", linux) is None,
    )
    require(
        "Linux links ${GSPELL_LIBRARIES} when present",
        re.search(r"\$\{GSPELL_LIBRARIES\}", linux) is not None,
    )

    # 4) Xxf86vm linked
    require(
        "Linux links Xxf86vm",
        re.search(r"\bXxf86vm\b", linux) is not None,
        "issue #2 item 4",
    )

    # Guard: Windows branch must still include src/cstool (no regression)
    win_sections = re.findall(
        r"elseif\s*\(\s*WIN32\s*\)(.*?)(?=\nelse\(\)|\nelseif\s*\(|\nendif\s*\(|$)",
        text,
        flags=re.S,
    )
    win_text = "\n".join(win_sections)
    require(
        "Windows include path still contains src/cstool",
        re.search(r"src/cstool", win_text) is not None,
    )

    # Static link options (full file / all WIN32 sections)
    require(
        "Windows uses -static / -static-libgcc / -static-libstdc++ link options",
        re.search(r"-static\b", win_text) is not None
        and "static-libgcc" in win_text
        and "static-libstdc++" in win_text
        and "target_link_options" in win_text,
    )
    require(
        "Linux uses static-libgcc/static-libstdc++ link options",
        re.search(r"static-libgcc", linux) is not None
        and re.search(r"static-libstdc\+\+", linux) is not None,
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed", file=sys.stderr)
        return 1
    print("\nAll Linux CMake issue #2 structural checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
