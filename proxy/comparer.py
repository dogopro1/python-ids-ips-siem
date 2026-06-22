"""
BurpSuite Comparer equivalent — diff two pieces of text.

Modes:
  words — tokenize by whitespace/delimiters and diff word-by-word
  lines — diff line by line (like diff -u)
  chars — character-level diff

Returns diff_html (for browser display) and diff_summary.
"""
import difflib
import re


def _tokenize_words(text: str) -> list:
    return re.findall(r"\S+|\s+", text)


def compare_words(left: str, right: str) -> dict:
    """Word-level diff. Returns {diff_html, added, removed, unchanged}."""
    left_words = _tokenize_words(left)
    right_words = _tokenize_words(right)

    matcher = difflib.SequenceMatcher(None, left_words, right_words, autojunk=False)
    left_html = []
    right_html = []
    added = removed = unchanged = 0

    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        l_chunk = "".join(left_words[i1:i2])
        r_chunk = "".join(right_words[j1:j2])
        if op == "equal":
            _esc = _escape(l_chunk)
            left_html.append(_esc)
            right_html.append(_esc)
            unchanged += len(left_words[i1:i2])
        elif op == "replace":
            left_html.append(f'<span class="diff-del">{_escape(l_chunk)}</span>')
            right_html.append(f'<span class="diff-add">{_escape(r_chunk)}</span>')
            removed += len(left_words[i1:i2])
            added += len(right_words[j1:j2])
        elif op == "delete":
            left_html.append(f'<span class="diff-del">{_escape(l_chunk)}</span>')
            removed += len(left_words[i1:i2])
        elif op == "insert":
            right_html.append(f'<span class="diff-add">{_escape(r_chunk)}</span>')
            added += len(right_words[j1:j2])

    return {
        "mode": "words",
        "left_html": "".join(left_html),
        "right_html": "".join(right_html),
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "similarity": round(matcher.ratio() * 100, 1),
    }


def compare_lines(left: str, right: str) -> dict:
    """Line-level unified diff."""
    left_lines = left.splitlines(keepends=True)
    right_lines = right.splitlines(keepends=True)

    diff = list(difflib.unified_diff(left_lines, right_lines,
                                     fromfile="Left", tofile="Right", lineterm=""))

    left_table = []
    right_table = []
    added = removed = unchanged = 0

    matcher = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        l_chunk = "".join(left_lines[i1:i2])
        r_chunk = "".join(right_lines[j1:j2])
        if op == "equal":
            left_table.append(_escape(l_chunk))
            right_table.append(_escape(r_chunk))
            unchanged += i2 - i1
        elif op == "replace":
            left_table.append(f'<span class="diff-del">{_escape(l_chunk)}</span>')
            right_table.append(f'<span class="diff-add">{_escape(r_chunk)}</span>')
            removed += i2 - i1
            added += j2 - j1
        elif op == "delete":
            left_table.append(f'<span class="diff-del">{_escape(l_chunk)}</span>')
            removed += i2 - i1
        elif op == "insert":
            right_table.append(f'<span class="diff-add">{_escape(r_chunk)}</span>')
            added += j2 - j1

    return {
        "mode": "lines",
        "left_html": "".join(left_table),
        "right_html": "".join(right_table),
        "unified_diff": "\n".join(diff[:200]),
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "similarity": round(difflib.SequenceMatcher(None, left_lines, right_lines).ratio() * 100, 1),
    }


def compare_chars(left: str, right: str) -> dict:
    """Character-level diff."""
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    left_html = []
    right_html = []
    added = removed = unchanged = 0

    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            chunk = _escape(left[i1:i2])
            left_html.append(chunk)
            right_html.append(chunk)
            unchanged += i2 - i1
        elif op == "replace":
            left_html.append(f'<span class="diff-del">{_escape(left[i1:i2])}</span>')
            right_html.append(f'<span class="diff-add">{_escape(right[j1:j2])}</span>')
            removed += i2 - i1
            added += j2 - j1
        elif op == "delete":
            left_html.append(f'<span class="diff-del">{_escape(left[i1:i2])}</span>')
            removed += i2 - i1
        elif op == "insert":
            right_html.append(f'<span class="diff-add">{_escape(right[j1:j2])}</span>')
            added += j2 - j1

    return {
        "mode": "chars",
        "left_html": "".join(left_html),
        "right_html": "".join(right_html),
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "similarity": round(matcher.ratio() * 100, 1),
    }


def compare(left: str, right: str, mode: str = "words") -> dict:
    """Entry point. mode: words | lines | chars."""
    if mode == "lines":
        result = compare_lines(left, right)
    elif mode == "chars":
        result = compare_chars(left, right)
    else:
        result = compare_words(left, right)

    result["left_len"] = len(left)
    result["right_len"] = len(right)
    result["len_diff"] = len(right) - len(left)
    return result


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
