"""Dataset record index and diff, per 02_TECHNICAL_ARCHITECTURE.md section 3.4.

v1 supports JSONL specifically: a per-file index of record digests at
configurable granularity (one digest per line, or one digest per block of
N lines). This is T3B's detective mitigation for publisher-signed poison:
injected/duplicated samples and label flips between versions become
enumerable, attributable facts tied to a signed release, rather than
something hidden inside a multi-gigabyte blob.

The diff is positional (record i in the old index vs. record i in the new
one), matching how JSONL datasets actually evolve (mostly appended to, so
"modified" means "the record at this position changed," not "this exact
content moved somewhere else").
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .errors import UsageError
from .hashing import b3_hex

GRANULARITY_NONE = "none"
GRANULARITY_LINE = "line"


def parse_granularity(spec: str) -> tuple[str, int]:
    """Parse a `--records` CLI value: 'none', 'line', or 'block:N'. Returns
    (kind, block_size) where kind is 'none'|'line'|'block' and block_size
    is the number of JSONL lines per digest (1 for 'line', 0 for 'none').
    """
    if spec == GRANULARITY_NONE:
        return GRANULARITY_NONE, 0
    if spec == GRANULARITY_LINE:
        return GRANULARITY_LINE, 1
    if spec.startswith("block:"):
        try:
            n = int(spec[len("block:"):])
        except ValueError:
            raise UsageError(f"invalid --records value {spec!r}: expected none, line, or block:N")
        if n < 1:
            raise UsageError(f"invalid --records value {spec!r}: block size must be >= 1")
        return "block", n
    raise UsageError(f"invalid --records value {spec!r}: expected none, line, or block:N")


def build_record_index(path: Path, granularity: str) -> list[str] | None:
    """Build a per-file record digest list for a JSONL file. Returns None
    for granularity 'none'.
    """
    kind, n = parse_granularity(granularity)
    if kind == GRANULARITY_NONE:
        return None

    digests: list[str] = []
    block_lines: list[bytes] = []
    with open(path, "rb") as f:
        for line in f:
            block_lines.append(line)
            if len(block_lines) >= n:
                digests.append(b3_hex(b"".join(block_lines)))
                block_lines = []
    if block_lines:
        digests.append(b3_hex(b"".join(block_lines)))
    return digests


def diff_record_indices(old: list[str] | None, new: list[str] | None) -> dict:
    """Positional diff between two record-digest lists. Both must be
    present (i.e. both versions were published with a non-'none' record
    index) -- there's nothing meaningful to diff otherwise.
    """
    if old is None or new is None:
        raise UsageError("both versions must have a record index (published with --records line|block:N) to diff")

    common_len = min(len(old), len(new))
    modified = [i for i in range(common_len) if old[i] != new[i]]
    added_indices = list(range(len(old), len(new))) if len(new) > len(old) else []
    removed_indices = list(range(len(new), len(old))) if len(old) > len(new) else []

    added_digests = [new[i] for i in added_indices]
    removed_digests = [old[i] for i in removed_indices]
    duplicate_counts = Counter(added_digests)
    duplicates_among_added = sorted(d for d, count in duplicate_counts.items() if count > 1)

    return {
        "vouch": "diff/v1",
        "old_count": len(old),
        "new_count": len(new),
        "added_count": len(added_indices),
        "removed_count": len(removed_indices),
        "modified_count": len(modified),
        "added_digests": added_digests,
        "removed_digests": removed_digests,
        "modified": [{"index": i, "old_digest": old[i], "new_digest": new[i]} for i in modified],
        "duplicates_among_added": duplicates_among_added,
    }
