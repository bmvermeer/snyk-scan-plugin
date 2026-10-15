"""Classify a path as a source file, a dependency file, or neither (REQ-1, REQ-2).

The lists mirror the spec ("Technical context"). Change both together.
"""

SOURCE_EXTENSIONS = frozenset(
    ".js .jsx .mjs .cjs .ts .tsx .mts .cts .vue .py .java .kt .kts .scala .groovy "
    ".go .rb .php .cs .vb .c .h .cc .cpp .cxx .hpp .m .mm .swift .dart .rs .ex .exs "
    ".cls .trigger".split()
)

DEPENDENCY_NAMES = frozenset(
    "package.json package-lock.json yarn.lock pnpm-lock.yaml requirements.txt Pipfile "
    "Pipfile.lock poetry.lock pyproject.toml pom.xml build.gradle build.gradle.kts go.mod "
    "go.sum Gemfile Gemfile.lock packages.lock.json composer.json composer.lock".split()
)

DEPENDENCY_EXTENSIONS = frozenset([".csproj"])

SOURCE = "source"
DEPENDENCY = "dependency"


def classify(path):
    """Return "source", "dependency", or None. Accepts / or \\ separators."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    if name in DEPENDENCY_NAMES:
        return DEPENDENCY
    dot = name.rfind(".")
    ext = name[dot:].lower() if dot > 0 else ""
    if ext in DEPENDENCY_EXTENSIONS:
        return DEPENDENCY
    if ext in SOURCE_EXTENSIONS:
        return SOURCE
    return None
