from dataclasses import dataclass, field
from enum import Enum


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------- complexity

@dataclass
class FunctionComplexity:
    file: str
    name: str
    lineno: int
    complexity: int
    risk: Risk


@dataclass
class FileMaintainability:
    file: str
    maintainability_index: float


@dataclass
class ComplexityResult:
    functions: list[FunctionComplexity] = field(default_factory=list)
    files: list[FileMaintainability] = field(default_factory=list)

    @property
    def total_functions(self) -> int:
        return len(self.functions)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.functions if f.risk is Risk.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.functions if f.risk is Risk.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.functions if f.risk is Risk.LOW)

    @property
    def average_complexity(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.complexity for f in self.functions) / len(self.functions)


# -------------------------------------------------------------- static (pylint)

@dataclass
class StaticIssue:
    file: str
    line: int
    column: int
    symbol: str
    message: str
    category: str  # error | warning | convention | refactor


@dataclass
class StaticResult:
    issues: list[StaticIssue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.category == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.category == "warning")

    @property
    def convention_count(self) -> int:
        return sum(1 for i in self.issues if i.category == "convention")

    @property
    def refactor_count(self) -> int:
        return sum(1 for i in self.issues if i.category == "refactor")

    @property
    def total_count(self) -> int:
        return len(self.issues)


# ------------------------------------------------------------- dead code (vulture)

@dataclass
class DeadCodeItem:
    file: str
    lineno: int
    name: str
    type: str
    confidence: int
    size: int


@dataclass
class DeadCodeResult:
    items: list[DeadCodeItem] = field(default_factory=list)
    total_lines: int = 0

    @property
    def dead_lines(self) -> int:
        return sum(i.size for i in self.items)

    @property
    def dead_ratio(self) -> float:
        if not self.total_lines:
            return 0.0
        return self.dead_lines / self.total_lines


# --------------------------------------------------------------- security (bandit)

@dataclass
class SecurityIssue:
    file: str
    line: int
    severity: str  # low | medium | high
    confidence: str
    test_id: str
    issue: str


@dataclass
class SecurityResult:
    issues: list[SecurityIssue] = field(default_factory=list)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "low")


# ------------------------------------------------------- dependencies (pip-audit)

@dataclass
class VulnerablePackage:
    name: str
    installed_version: str
    vulnerability_id: str
    fix_versions: list[str]
    description: str


@dataclass
class DependencyResult:
    scanned: bool = False
    source_file: str | None = None
    vulnerable: list[VulnerablePackage] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return len(self.vulnerable)


# --------------------------------------------------------------- coverage

@dataclass
class FileCoverage:
    file: str
    percent_covered: float
    missing_lines: list[int]


@dataclass
class CoverageResult:
    available: bool = False
    reason: str = ""
    overall_pct: float = 0.0
    files: list[FileCoverage] = field(default_factory=list)

    @property
    def zero_coverage_files(self) -> list[FileCoverage]:
        return [f for f in self.files if f.percent_covered == 0]


# ------------------------------------------------------------------- aggregate

@dataclass
class AuditResults:
    complexity: ComplexityResult
    static: StaticResult
    deadcode: DeadCodeResult
    security: SecurityResult
    dependencies: DependencyResult
    coverage: CoverageResult
