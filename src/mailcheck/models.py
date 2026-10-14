"""Data model shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """One thing the check found. ``ok`` findings are positive results."""

    check: str
    severity: Severity
    message: str
    remediation: str = ""
    ok: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass
class Report:
    domain: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding | None) -> None:
        if finding is not None:
            self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def issues(self) -> list[Finding]:
        return [f for f in self.findings if not f.ok]

    @property
    def score(self) -> int:
        penalty = {Severity.INFO: 0, Severity.LOW: 3, Severity.MEDIUM: 10, Severity.HIGH: 25}
        return max(0, 100 - sum(penalty[f.severity] for f in self.issues))

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if score >= threshold:
                return letter
        return "F"

    def worst(self) -> Severity | None:
        issues = self.issues
        return max((f.severity for f in issues), default=None)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
        }
