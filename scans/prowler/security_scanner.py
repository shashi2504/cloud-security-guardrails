"""
Security Score Calculator
Standalone module for computing, tracking, and comparing
security scores across scans. Imported by prowler_scanner.py
and usable independently for CLI reporting.

Usage:
  from security_score import SecurityScoreCalculator

  calculator = SecurityScoreCalculator(project_name="cloud-sec-guardrails")
  score      = calculator.calculate(processed_findings)
  trend      = calculator.get_trend(days=30)
  delta      = calculator.compare_to_previous(score)
"""

import boto3
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
# DATA CLASSES
# Typed structures for scores — no raw dicts floating around
# ─────────────────────────────────────────────────────────

@dataclass
class SeverityBreakdown:
    critical: int = 0
    high:     int = 0
    medium:   int = 0
    low:      int = 0


@dataclass
class ScoreComponents:
    """
    Breakdown of how the final score was calculated.
    Stored alongside the score for auditability.
    """
    base_score:          float = 100.0
    critical_deduction:  float = 0.0
    high_deduction:      float = 0.0
    medium_deduction:    float = 0.0
    total_deduction:     float = 0.0
    final_score:         float = 100.0


@dataclass
class SecurityScore:
    """Complete security score for one scan."""
    scan_id:    str
    timestamp:  str
    score:      float
    rating:     str
    pass_rate:  float

    # Finding counts
    total:    int
    passed:   int
    failed:   int
    critical: int
    high:     int
    medium:   int

    # Score breakdown — shows exactly why score is X
    components: ScoreComponents = field(default_factory=ScoreComponents)

    # Delta vs previous scan — None on first scan
    delta:            Optional[float] = None
    delta_direction:  Optional[str]   = None    # "IMPROVED", "DECLINED", "UNCHANGED"
    previous_score:   Optional[float] = None


@dataclass
class ScoreTrend:
    """Trend data across multiple scans."""
    period_days:   int
    scan_count:    int
    latest_score:  float
    highest_score: float
    lowest_score:  float
    average_score: float
    trend:         str       # "IMPROVING", "DECLINING", "STABLE"
    scores:        list      # List of (timestamp, score) tuples


# ─────────────────────────────────────────────────────────
# SCORE WEIGHTS
# Centralised constants — change here to affect everything
# ─────────────────────────────────────────────────────────

class ScoreWeights:
    # Points deducted per finding of each severity
    CRITICAL_PER_FINDING = 15
    HIGH_PER_FINDING     = 5
    MEDIUM_PER_FINDING   = 1

    # Maximum deduction per severity category
    # Prevents a flood of medium findings collapsing the score unfairly
    CRITICAL_CAP = 60
    HIGH_CAP     = 30
    MEDIUM_CAP   = 10

    # Score thresholds for rating labels
    RATINGS = [
        (90,  "EXCELLENT"),
        (75,  "GOOD"),
        (60,  "FAIR"),
        (40,  "POOR"),
        (0,   "CRITICAL"),
    ]

    # Delta thresholds
    IMPROVED_THRESHOLD  = 1.0    # Score must rise by 1+ to be "IMPROVED"
    DECLINED_THRESHOLD  = 1.0    # Score must drop by 1+ to be "DECLINED"

    # Trend thresholds (across multiple scans)
    TREND_IMPROVING_THRESHOLD = 2.0   # Average gain per scan
    TREND_DECLINING_THRESHOLD = 2.0   # Average loss per scan


# ─────────────────────────────────────────────────────────
# CALCULATOR
# ─────────────────────────────────────────────────────────

class SecurityScoreCalculator:
    """
    Calculates, stores, and retrieves security scores.
    Single responsibility — knows about scores only,
    not findings parsing or alerting.
    """

    def __init__(self, project_name: str, region: str = None):
        self.project_name  = project_name
        self.region        = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.score_table   = os.environ.get(
            "SCORE_TABLE",
            f"{project_name}-cspm-scores"
        )
        self._dynamodb     = None    # Lazy init — not needed for pure calc

    @property
    def dynamodb(self):
        """Lazy DynamoDB initialisation — avoids connection on import."""
        if self._dynamodb is None:
            self._dynamodb = boto3.resource("dynamodb", region_name=self.region)
        return self._dynamodb

    # ─────────────────────────────────────────────────
    # CORE CALCULATION
    # ─────────────────────────────────────────────────

    def calculate(self, processed_findings: dict, scan_id: str = None) -> SecurityScore:
        """
        Calculate security score from processed findings dict.

        Args:
            processed_findings: Output from findings_processor.process_findings()
            scan_id: Optional — generated from timestamp if not provided

        Returns:
            SecurityScore dataclass with full breakdown
        """
        timestamp = processed_findings.get(
            "timestamp",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        )
        scan_id = scan_id or processed_findings.get(
            "scan_id",
            f"scan-{timestamp}"
        )

        # Raw counts
        total    = processed_findings.get("total",   0)
        passed   = len(processed_findings.get("passed",   []))
        failed   = len(processed_findings.get("failed",   []))
        critical = len(processed_findings.get("critical", []))
        high     = len(processed_findings.get("high",     []))
        medium   = len(processed_findings.get("medium",   []))

        # Score components
        components = self._compute_components(critical, high, medium)

        # Pass rate
        pass_rate = round((passed / total * 100), 2) if total > 0 else 0.0

        # Rating label
        rating = self._get_rating(components.final_score)

        # Compare to previous scan
        previous   = self._get_previous_score()
        delta      = None
        direction  = None
        prev_score = None

        if previous:
            prev_score = float(previous.get("score", 0))
            delta      = round(components.final_score - prev_score, 2)
            direction  = self._get_delta_direction(delta)

        score = SecurityScore(
            scan_id          = scan_id,
            timestamp        = timestamp,
            score            = components.final_score,
            rating           = rating,
            pass_rate        = pass_rate,
            total            = total,
            passed           = passed,
            failed           = failed,
            critical         = critical,
            high             = high,
            medium           = medium,
            components       = components,
            delta            = delta,
            delta_direction  = direction,
            previous_score   = prev_score,
        )

        logger.info(
            "Score calculated: %.1f/100 (%s) | Δ%s%s | "
            "Critical: %d | High: %d | Medium: %d",
            score.score,
            score.rating,
            "+" if (delta or 0) >= 0 else "",
            f"{delta:.1f}" if delta is not None else "N/A",
            critical, high, medium,
        )

        return score

    def _compute_components(
        self,
        critical: int,
        high:     int,
        medium:   int
    ) -> ScoreComponents:
        """
        Apply weighted deductions with per-category caps.
        Returns full breakdown so score is fully auditable.
        """
        w = ScoreWeights

        critical_deduction = min(critical * w.CRITICAL_PER_FINDING, w.CRITICAL_CAP)
        high_deduction     = min(high     * w.HIGH_PER_FINDING,     w.HIGH_CAP)
        medium_deduction   = min(medium   * w.MEDIUM_PER_FINDING,   w.MEDIUM_CAP)
        total_deduction    = critical_deduction + high_deduction + medium_deduction
        final_score        = round(max(0.0, 100.0 - total_deduction), 2)

        return ScoreComponents(
            base_score         = 100.0,
            critical_deduction = critical_deduction,
            high_deduction     = high_deduction,
            medium_deduction   = medium_deduction,
            total_deduction    = total_deduction,
            final_score        = final_score,
        )

    def _get_rating(self, score: float) -> str:
        """Map numeric score to human-readable rating."""
        for threshold, label in ScoreWeights.RATINGS:
            if score >= threshold:
                return label
        return "CRITICAL"

    def _get_delta_direction(self, delta: float) -> str:
        """Classify score change direction."""
        w = ScoreWeights
        if delta >= w.IMPROVED_THRESHOLD:
            return "IMPROVED"
        elif delta <= -w.DECLINED_THRESHOLD:
            return "DECLINED"
        return "UNCHANGED"

    # ─────────────────────────────────────────────────
    # DYNAMODB PERSISTENCE
    # ─────────────────────────────────────────────────

    def save(self, score: SecurityScore):
        """
        Persist score to DynamoDB for trend tracking.
        Called by prowler_scanner.py after every scan.
        """
        table = self.dynamodb.Table(self.score_table)

        item = {
            "scan_id":           score.scan_id,
            "timestamp":         score.timestamp,
            "score":             str(round(score.score, 2)),
            "rating":            score.rating,
            "pass_rate":         str(score.pass_rate),
            "total":             score.total,
            "passed":            score.passed,
            "failed":            score.failed,
            "critical":          score.critical,
            "high":              score.high,
            "medium":            score.medium,

            # Store full component breakdown
            "components": {
                "base_score":          str(score.components.base_score),
                "critical_deduction":  str(score.components.critical_deduction),
                "high_deduction":      str(score.components.high_deduction),
                "medium_deduction":    str(score.components.medium_deduction),
                "total_deduction":     str(score.components.total_deduction),
                "final_score":         str(score.components.final_score),
            },

            # Delta vs previous
            "delta":           str(score.delta)          if score.delta          is not None else "N/A",
            "delta_direction": score.delta_direction      if score.delta_direction is not None else "N/A",
            "previous_score":  str(score.previous_score) if score.previous_score is not None else "N/A",

            # TTL — auto-expire after 1 year
            "ttl": int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
        }

        table.put_item(Item=item)
        logger.info("Score saved to DynamoDB: scan_id=%s score=%s", score.scan_id, score.score)

    def _get_previous_score(self) -> Optional[dict]:
        """
        Fetch the most recent score from DynamoDB.
        Returns None if this is the first scan.
        """
        try:
            table    = self.dynamodb.Table(self.score_table)
            response = table.scan(
                ProjectionExpression="scan_id, #ts, score",
                ExpressionAttributeNames={"#ts": "timestamp"},
            )

            items = sorted(
                response.get("Items", []),
                key=lambda x: x["timestamp"],
                reverse=True
            )

            return items[0] if items else None

        except Exception as e:
            logger.warning("Could not fetch previous score: %s", str(e))
            return None

    # ─────────────────────────────────────────────────
    # TREND ANALYSIS
    # ─────────────────────────────────────────────────

    def get_trend(self, days: int = 30) -> ScoreTrend:
        """
        Analyse score trend across multiple scans.
        Used by metrics_publisher and CLI reporting.
        """
        cutoff     = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H-%M-%SZ")

        table    = self.dynamodb.Table(self.score_table)
        response = table.scan(
            FilterExpression=Attr("timestamp").gte(cutoff_str)
        )

        items = sorted(
            response.get("Items", []),
            key=lambda x: x["timestamp"]
        )

        if not items:
            logger.warning("No scores found in last %d days", days)
            return ScoreTrend(
                period_days   = days,
                scan_count    = 0,
                latest_score  = 0.0,
                highest_score = 0.0,
                lowest_score  = 0.0,
                average_score = 0.0,
                trend         = "INSUFFICIENT_DATA",
                scores        = [],
            )

        scores_list = [(item["timestamp"], float(item["score"])) for item in items]
        score_vals  = [s[1] for s in scores_list]

        latest_score  = score_vals[-1]
        highest_score = max(score_vals)
        lowest_score  = min(score_vals)
        average_score = round(sum(score_vals) / len(score_vals), 2)

        # Trend direction — compare first half vs second half average
        trend = self._compute_trend_direction(score_vals)

        return ScoreTrend(
            period_days   = days,
            scan_count    = len(items),
            latest_score  = latest_score,
            highest_score = highest_score,
            lowest_score  = lowest_score,
            average_score = average_score,
            trend         = trend,
            scores        = scores_list,
        )

    def _compute_trend_direction(self, scores: list) -> str:
        """
        Compare first half average vs second half average.
        Needs at least 2 scans — returns STABLE otherwise.
        """
        if len(scores) < 2:
            return "STABLE"

        mid        = len(scores) // 2
        first_avg  = sum(scores[:mid]) / len(scores[:mid])
        second_avg = sum(scores[mid:]) / len(scores[mid:])
        delta      = second_avg - first_avg

        w = ScoreWeights
        if delta >= w.TREND_IMPROVING_THRESHOLD:
            return "IMPROVING"
        elif delta <= -w.TREND_DECLINING_THRESHOLD:
            return "DECLINING"
        return "STABLE"

    # ─────────────────────────────────────────────────
    # REPORTING HELPERS
    # ─────────────────────────────────────────────────

    def format_score_report(self, score: SecurityScore) -> str:
        """
        Human-readable score report.
        Used in SNS alerts and CLI output.
        """
        delta_str = "N/A (first scan)"
        if score.delta is not None:
            sign      = "+" if score.delta >= 0 else ""
            direction = score.delta_direction or ""
            delta_str = f"{sign}{score.delta:.1f} ({direction}) vs previous: {score.previous_score:.1f}"

        deduction_breakdown = (
            f"  Critical: -{score.components.critical_deduction:.0f} pts "
            f"({score.critical} findings × {ScoreWeights.CRITICAL_PER_FINDING}, "
            f"capped at {ScoreWeights.CRITICAL_CAP})\n"
            f"  High:     -{score.components.high_deduction:.0f} pts "
            f"({score.high} findings × {ScoreWeights.HIGH_PER_FINDING}, "
            f"capped at {ScoreWeights.HIGH_CAP})\n"
            f"  Medium:   -{score.components.medium_deduction:.0f} pts "
            f"({score.medium} findings × {ScoreWeights.MEDIUM_PER_FINDING}, "
            f"capped at {ScoreWeights.MEDIUM_CAP})"
        )

        return f"""
╔══════════════════════════════════════════════════╗
║         SECURITY SCORE REPORT                   ║
╠══════════════════════════════════════════════════╣
  Scan ID:       {score.scan_id}
  Timestamp:     {score.timestamp}
──────────────────────────────────────────────────
  SCORE:         {score.score:.1f} / 100  [{score.rating}]
  Change:        {delta_str}
──────────────────────────────────────────────────
  FINDINGS
  Total Checks:  {score.total}
  Passed:        {score.passed}  ({score.pass_rate:.1f}% pass rate)
  Failed:        {score.failed}
    Critical:    {score.critical}
    High:        {score.high}
    Medium:      {score.medium}
──────────────────────────────────────────────────
  SCORE BREAKDOWN (deductions from 100)
{deduction_breakdown}
  Total deducted: -{score.components.total_deduction:.0f} pts
╚══════════════════════════════════════════════════╝
"""

    def format_trend_report(self, trend: ScoreTrend) -> str:
        """Human-readable trend report for CLI and Slack."""
        if trend.scan_count == 0:
            return "No scan data available for trend analysis."

        spark = self._sparkline(trend.scores)

        return f"""
╔══════════════════════════════════════════════════╗
║         SECURITY SCORE TREND ({trend.period_days} days)        ║
╠══════════════════════════════════════════════════╣
  Scans analysed: {trend.scan_count}
  Trend:          {trend.trend}
──────────────────────────────────────────────────
  Latest score:   {trend.latest_score:.1f}
  Highest:        {trend.highest_score:.1f}
  Lowest:         {trend.lowest_score:.1f}
  Average:        {trend.average_score:.1f}
──────────────────────────────────────────────────
  Sparkline (oldest → newest):
  {spark}
╚══════════════════════════════════════════════════╝
"""

    def _sparkline(self, scores: list, width: int = 20) -> str:
        """
        Generate a simple ASCII sparkline from score history.
        Maps scores 0-100 to block characters.
        """
        if not scores:
            return "No data"

        # 8 block levels
        blocks = "▁▂▃▄▅▆▇█"
        vals   = [s[1] for s in scores]

        # Normalise to 0-7 range
        min_val = min(vals)
        max_val = max(vals)
        spread  = max_val - min_val or 1

        chars = []
        for v in vals[-width:]:    # Last `width` scans
            idx = int((v - min_val) / spread * 7)
            chars.append(blocks[min(idx, 7)])

        return "".join(chars) + f"  ({vals[-1]:.0f}/100)"

    def to_dict(self, score: SecurityScore) -> dict:
        """Serialise SecurityScore to plain dict for JSON/DynamoDB."""
        d = asdict(score)
        return d


# ─────────────────────────────────────────────────────────
# CLI ENTRY POINT
# Run directly: python security_score.py --trend --days 30
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level  = logging.INFO,
        format = "%(asctime)s [%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Security Score Tool")
    parser.add_argument(
        "--trend",
        action="store_true",
        help="Show score trend"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days for trend (default: 30)"
    )
    parser.add_argument(
        "--project",
        type=str,
        default=os.environ.get("PROJECT_NAME", "cloud-sec-guardrails"),
        help="Project name"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON"
    )
    args = parser.parse_args()

    calculator = SecurityScoreCalculator(project_name=args.project)

    if args.trend:
        trend = calculator.get_trend(days=args.days)
        if args.json:
            print(json.dumps(asdict(trend), indent=2, default=str))
        else:
            print(calculator.format_trend_report(trend))
