"""Launch-flow v2 anchor-only acceptance (§6.5, freeze decision 1).

There are no signed pins, no ``pin_seq``, and no pin store in v2. An
anchor is accepted as an authenticator only when the whole predicate
below is composed and true:

* payload binding — the claimed payload equals the fetched tx's
  OP_RETURN output;
* transaction-signature verification — the anchor input is signed by
  the trusted anchor key;
* inclusion verification — SPV/BUMP, or BEEF with mined (``bump``)
  status. Ancestry-only BEEF never counts;
* header-chain verification — the anchor's block chains back to an
  operator-pinned checkpoint, within the 4032-header cap (3887 with
  ``--daa``). The walk starts at the anchor's block, never at the tip.

Freshness is still not provided. No tip service is consulted, a
shorter anchor set is not detected, and an empty anchor list is
"freshness unavailable", never "current".

The result reports two named verdicts — ``prefix_matches_anchor`` and
``tip_inside_anchor`` — because a single boolean would be read as
completion. ``authentication`` is either ``"accepted"`` or
``"withheld"``; a failed check withholds authentication, it does not
raise.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .anchor import (
    apply_anchor_signatures,
    apply_header_chain,
    apply_payload_binding,
    verify_journal_against_anchor_chain,
)
from .beef import apply_beef_inclusion
from .core import VerificationError, journal_genesis_identity_for_path
from .spv import apply_bump_inclusion, apply_chain_inclusion

INCLUSION_SPV = "spv"
INCLUSION_BUMP = "bump"
INCLUSION_BEEF = "beef"
INCLUSION_METHODS = frozenset({INCLUSION_SPV, INCLUSION_BUMP, INCLUSION_BEEF})

AUTHENTICATION_ACCEPTED = "accepted"
AUTHENTICATION_WITHHELD = "withheld"

FRESHNESS_UNAVAILABLE = "unavailable"

VERDICT_PREFIX = "prefix matches anchor"
VERDICT_TIP = "tip inside anchor"


def _anchor_summaries(result: Mapping[str, Any]) -> list[dict]:
    """Return per-anchor summaries from either result shape."""
    chain = result.get("chain")
    if isinstance(chain, Mapping):
        summaries = chain.get("anchors")
    else:
        summaries = result.get("anchors")
    if not isinstance(summaries, list):
        return []
    return [summary for summary in summaries if isinstance(summary, dict)]


def _all_verified(summaries: Sequence[Mapping[str, Any]], field: str) -> bool:
    """True only when the list is non-empty and every anchor says yes."""
    return bool(summaries) and all(bool(s.get(field)) for s in summaries)


def _inclusion_verified(
    result: Mapping[str, Any],
    summaries: Sequence[Mapping[str, Any]],
    inclusion: str,
) -> bool:
    if inclusion == INCLUSION_SPV:
        return bool(result.get("chain_inclusion_verified")) and _all_verified(
            summaries, "chain_inclusion_verified"
        )
    if inclusion == INCLUSION_BUMP:
        return bool(result.get("bump_inclusion_verified")) and _all_verified(
            summaries, "bump_inclusion_verified"
        )
    if inclusion == INCLUSION_BEEF:
        if not result.get("beef_inclusion_verified"):
            return False
        for summary in summaries:
            if not summary.get("beef_inclusion_verified"):
                return False
            details = summary.get("beef_inclusion")
            # Belt and braces: ancestry-only is not block inclusion even
            # if a caller somehow set the per-anchor boolean.
            if not isinstance(details, Mapping):
                return False
            if details.get("status") != "bump":
                return False
        return bool(summaries)
    raise VerificationError(f"unknown inclusion method: {inclusion!r}")


def _identity_matches(
    journal_identity: Mapping[str, Any] | None,
    expected: str | None,
) -> tuple[bool, list[str]]:
    """Validate the identity shape and compare an optional pinned value."""
    if journal_identity is None:
        return True, []
    if not isinstance(journal_identity, Mapping):
        return False, ["journal identity is not an object"]
    identity = journal_identity.get("identity")
    genesis_hash = journal_identity.get("genesis_hash")
    nonce = journal_identity.get("genesis_nonce")
    if (
        not isinstance(identity, str)
        or len(identity) != 64
        or not isinstance(genesis_hash, str)
        or len(genesis_hash) != 64
        or not isinstance(nonce, str)
        or len(nonce) != 32
    ):
        return False, [
            "journal identity must be genesis hash WITH a nonce, "
            "never a bare genesis hash"
        ]
    if expected is not None and identity != expected:
        return False, [
            "journal identity does not match the expected identity"
        ]
    return True, []


def evaluate_anchor_acceptance(
    result: Mapping[str, Any],
    *,
    inclusion: str,
    terminal_seq: int | None = None,
    journal_identity: Mapping[str, Any] | None = None,
    expected_journal_identity: str | None = None,
) -> dict[str, Any]:
    """Evaluate the anchor-only acceptance predicate over composed checks.

    ``result`` must already carry the outputs of payload binding, anchor
    signature verification, the selected inclusion check, and header
    chain verification (the chain wrapper's two result shapes both
    work). This function does not fetch anything; it is the single
    place that decides whether those checks together authenticate an
    anchor.

    ``terminal_seq``, when supplied, adds a separate
    ``terminal_inside_anchor`` report. It never substitutes for the two
    named verdicts.
    """
    if inclusion not in INCLUSION_METHODS:
        raise VerificationError(f"unknown inclusion method: {inclusion!r}")
    if terminal_seq is not None and (
        isinstance(terminal_seq, bool)
        or not isinstance(terminal_seq, int)
        or terminal_seq < 0
    ):
        raise VerificationError("terminal_seq must be a non-negative integer")

    summaries = _anchor_summaries(result)
    chain = result.get("chain") if isinstance(result.get("chain"), Mapping) else {}
    anchor_count = chain.get("anchor_count", result.get("anchor_count", 0))
    if isinstance(anchor_count, bool) or not isinstance(anchor_count, int):
        anchor_count = 0

    chain_verified = bool(chain.get("verified", result.get("verified")))
    payload_binding = bool(result.get("payload_binding_verified")) and (
        _all_verified(summaries, "payload_binding_verified")
    )
    anchor_signature = bool(result.get("anchor_signatures_verified")) and (
        _all_verified(summaries, "anchor_signature_verified")
    )
    inclusion_ok = _inclusion_verified(result, summaries, inclusion)
    header_chain = bool(result.get("header_chain_verified")) and (
        _all_verified(summaries, "header_chain_verified")
    )
    identity_ok, identity_reasons = _identity_matches(
        journal_identity, expected_journal_identity
    )

    unanchored = result.get("unanchored_events")
    if isinstance(unanchored, bool) or not isinstance(unanchored, int):
        unanchored = None

    reasons: list[str] = list(identity_reasons)
    summary_count_ok = len(summaries) == anchor_count
    if anchor_count == 0 or not summaries:
        reasons.append(
            "no anchors: freshness is unavailable and nothing can be "
            "authenticated (never \"current\")"
        )
    elif not summary_count_ok:
        reasons.append(
            "per-anchor results do not cover the claimed anchor count"
        )
    if not chain_verified:
        reasons.append("anchor chain continuity is not verified")
    if not payload_binding:
        reasons.append("payload binding is not verified")
    if not anchor_signature:
        reasons.append("anchor transaction signature is not verified")
    if not inclusion_ok:
        reasons.append(f"block inclusion is not verified ({inclusion})")
    if not header_chain:
        reasons.append("header chain back to the pinned checkpoint is not verified")
    if not identity_ok:
        reasons.append("journal identity is not verified")
    if unanchored is None:
        reasons.append(
            "unanchored tail is unknown: tip coverage cannot be claimed"
        )

    accepted = (
        anchor_count > 0
        and bool(summaries)
        and summary_count_ok
        and chain_verified
        and payload_binding
        and anchor_signature
        and inclusion_ok
        and header_chain
        and identity_ok
        and unanchored is not None
    )

    authenticated_prefix_end: int | None = None
    if accepted:
        last_seq = chain.get("last_seq")
        if isinstance(last_seq, int) and not isinstance(last_seq, bool):
            authenticated_prefix_end = last_seq
        else:
            accepted = False
            reasons.append("anchored prefix end is missing from the chain result")

    prefix_matches_anchor = accepted
    tip_inside_anchor = bool(accepted and unanchored == 0)
    terminal_inside_anchor: bool | None = None
    if terminal_seq is not None:
        terminal_inside_anchor = bool(
            authenticated_prefix_end is not None
            and terminal_seq <= authenticated_prefix_end
        )
        if not terminal_inside_anchor:
            reasons.append(
                f"terminal sequence {terminal_seq} is outside the "
                "authenticated anchor prefix"
            )

    return {
        "authentication": (
            AUTHENTICATION_ACCEPTED if accepted else AUTHENTICATION_WITHHELD
        ),
        "accepted": accepted,
        "inclusion_method": inclusion,
        "anchor_count": anchor_count,
        "predicate": {
            "journal_chain": chain_verified,
            "payload_binding": payload_binding,
            "anchor_signature": anchor_signature,
            "inclusion": inclusion_ok,
            "header_chain": header_chain,
            "journal_identity": identity_ok,
        },
        "authenticated_prefix_end": authenticated_prefix_end,
        "prefix_matches_anchor": prefix_matches_anchor,
        "tip_inside_anchor": tip_inside_anchor,
        "terminal_seq": terminal_seq,
        "terminal_inside_anchor": terminal_inside_anchor,
        "unanchored_events": unanchored,
        # Freshness is not provided by this verifier. An empty or short
        # anchor set is withheld, never reported as current.
        "freshness": FRESHNESS_UNAVAILABLE,
        "freshness_available": False,
        "journal_identity": dict(journal_identity)
        if isinstance(journal_identity, Mapping)
        else journal_identity,
        "verdicts": [
            {"name": VERDICT_PREFIX, "verified": prefix_matches_anchor},
            {"name": VERDICT_TIP, "verified": tip_inside_anchor},
        ],
        "reasons": reasons,
    }


def verify_v2_anchor_chain(
    journal: Path,
    anchors: Any,
    genesis_txid: Any,
    *,
    payload_fetcher: Any,
    signature_verifier: Any,
    inclusion: str,
    inclusion_verifier: Any,
    header_verifier: Any,
    bumps: Mapping[str, Any] | None = None,
    beef: Any = None,
    manifests: Any = None,
    public_key: Any = None,
    expected_journal_identity: str | None = None,
    terminal_seq: int | None = None,
) -> dict[str, Any]:
    """Compose the full v2 anchor-only acceptance predicate.

    The caller supplies the already-constructed fetchers/verifiers so
    the CLI and tests use the same composition. Structural chain
    failures (a broken chain, a journal that does not match an anchor)
    still raise :class:`VerificationError`; a check that simply does
    not verify withholds authentication and is reported, never raised.
    A missing or malformed journal raises :class:`VerificationError`
    from the identity helper, never a leaked ``FileNotFoundError``.

    ``bumps`` is required for ``inclusion="bump"``; ``beef`` is
    required for ``inclusion="beef"``.
    """
    if inclusion not in INCLUSION_METHODS:
        raise VerificationError(f"unknown inclusion method: {inclusion!r}")
    if inclusion == INCLUSION_BUMP and bumps is None:
        raise VerificationError("bump inclusion requires a BUMP mapping")
    if inclusion == INCLUSION_BEEF and beef is None:
        raise VerificationError("beef inclusion requires a parsed BEEF envelope")

    identity = journal_genesis_identity_for_path(journal)
    result = verify_journal_against_anchor_chain(
        journal, anchors, genesis_txid, manifests, public_key
    )
    result = apply_payload_binding(result, payload_fetcher)
    result = apply_anchor_signatures(result, signature_verifier)
    if inclusion == INCLUSION_SPV:
        result = apply_chain_inclusion(result, inclusion_verifier)
    elif inclusion == INCLUSION_BUMP:
        result = apply_bump_inclusion(result, inclusion_verifier, bumps)
    else:
        result = apply_beef_inclusion(result, inclusion_verifier, beef)
    result = apply_header_chain(result, header_verifier)

    acceptance = evaluate_anchor_acceptance(
        result,
        inclusion=inclusion,
        terminal_seq=terminal_seq,
        journal_identity=identity,
        expected_journal_identity=expected_journal_identity,
    )
    return {
        **result,
        "journal_identity": identity,
        "acceptance": acceptance,
    }
