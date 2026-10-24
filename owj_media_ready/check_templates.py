from pathlib import Path
from jinja2 import Environment

TEMPLATES = Path(__file__).parent / "templates"
env = Environment()
errors = []
for path in sorted(TEMPLATES.glob("*.html")):
    try:
        env.parse(path.read_text(encoding="utf-8"))
        print(f"OK  {path.name}")
    except Exception as exc:
        errors.append((path.name, exc))
        print(f"FAIL {path.name}: {exc}")
if errors:
    raise SystemExit(1)
print(f"\nAll {len(list(TEMPLATES.glob('*.html')))} templates passed syntax validation.")
