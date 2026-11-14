"""
benchmark/harness/statistics.py

Scientific statistical inference library for SentinelMesh evaluation:
- Wilson score confidence intervals for binomial proportions
- Bootstrap confidence intervals (10,000 resamples)
- Exact two-sided McNemar test for paired binary classifications
- Holm-Bonferroni step-down correction for multiple testing
- Effect sizes (Cohen's g, Odds Ratio)
"""

import math
import random
from typing import List, Tuple, Dict, Any, Callable, Optional


def wilson_score_interval(
    successes: int, total: int, confidence: float = 0.95
) -> Tuple[float, float, float]:
    """
    Computes the Wilson score interval for a binomial proportion.
    Returns: (point_estimate, lower_bound, upper_bound)
    """
    if total <= 0:
        return (0.0, 0.0, 0.0)

    p = successes / total
    # z-value for standard normal distribution
    # 0.95 -> 1.959964, 0.99 -> 2.575829
    if abs(confidence - 0.95) < 1e-3:
        z = 1.959963984540054
    elif abs(confidence - 0.99) < 1e-3:
        z = 2.5758293035489004
    else:
        # Fallback approximation for 95%
        z = 1.959963984540054

    z2 = z * z
    n = float(total)

    denominator = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denominator
    spread = (z * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))) / denominator

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)

    return (round(p, 4), round(lower, 4), round(upper, 4))


def bootstrap_ci(
    data: List[float],
    statistic_fn: Optional[Callable[[List[float]], float]] = None,
    n_resamples: int = 10000,
    alpha: float = 0.05,
    seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Computes empirical percentile bootstrap confidence interval with B=10,000 resamples.
    Returns: (point_estimate, lower_bound, upper_bound)
    """
    if not data:
        return (0.0, 0.0, 0.0)

    if statistic_fn is None:
        statistic_fn = lambda sample: sum(sample) / len(sample)

    rng = random.Random(seed)
    n = len(data)
    point_est = statistic_fn(data)

    boot_stats = []
    for _ in range(n_resamples):
        resample = [data[rng.randint(0, n - 1)] for _ in range(n)]
        boot_stats.append(statistic_fn(resample))

    boot_stats.sort()
    lower_idx = int(math.floor((alpha / 2.0) * n_resamples))
    upper_idx = int(math.ceil((1.0 - alpha / 2.0) * n_resamples)) - 1
    upper_idx = min(upper_idx, n_resamples - 1)

    return (
        round(point_est, 4),
        round(boot_stats[lower_idx], 4),
        round(boot_stats[upper_idx], 4),
    )


def exact_mcnemar_test(
    b: int, c: int
) -> Dict[str, Any]:
    """
    Exact two-sided McNemar test for paired binary outcomes.
    b: System A correct, System B incorrect
    c: System A incorrect, System B correct
    Under H0: p_b = p_c = 0.5.
    Returns exact binomial p-value, Cohen's g, and Odds Ratio.
    """
    n = b + c
    if n == 0:
        return {
            "b": b,
            "c": c,
            "n": 0,
            "p_value": 1.0,
            "cohens_g": 0.0,
            "odds_ratio": 1.0,
            "interpretation": "Identical performance (no discordant pairs)"
        }

    k = min(b, c)
    try:
        from scipy.stats import binomtest
        two_sided_p = float(binomtest(k, n, 0.5, alternative='two-sided').pvalue)
    except Exception:
        # Fallback to math log-space binomial test
        tail_prob = sum(math.comb(n, i) * (0.5 ** n) for i in range(k + 1))
        two_sided_p = min(1.0, 2.0 * tail_prob)

    # Cohen's g = | b / (b + c) - 0.5 |
    cohens_g = abs(b / float(n) - 0.5)

    # Odds ratio = b / c
    if c == 0:
        odds_ratio = float("inf") if b > 0 else 1.0
    else:
        odds_ratio = round(b / float(c), 4)

    interpretation = "statistically significant" if two_sided_p < 0.05 else "not statistically significant"

    return {
        "b": b,
        "c": c,
        "n": n,
        "p_value": two_sided_p,
        "cohens_g": round(cohens_g, 4),
        "odds_ratio": odds_ratio,
        "interpretation": interpretation
    }


def holm_bonferroni_correction(
    p_values: List[float], alpha: float = 0.05
) -> List[Dict[str, Any]]:
    """
    Applies Holm-Bonferroni step-down procedure to control Family-Wise Error Rate (FWER).
    Returns list of dicts with original index, raw p, threshold, and reject_null bool.
    """
    m = len(p_values)
    indexed_p = sorted(enumerate(p_values), key=lambda x: x[1])

    results = [None] * m
    stopped = False

    for rank, (orig_idx, p_val) in enumerate(indexed_p):
        k = rank + 1
        threshold = alpha / float(m - k + 1)
        if not stopped and p_val <= threshold:
            reject = True
        else:
            reject = False
            stopped = True

        results[orig_idx] = {
            "rank": k,
            "raw_p": p_val,
            "threshold": threshold,
            "reject_null": reject
        }

    return results
