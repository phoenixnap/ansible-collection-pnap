from pathlib import Path
import yaml

root = Path(__file__).resolve().parent
galaxy_file = root / "galaxy.yml"
version_file = root / "plugins" / "module_utils" / "version.py"

with galaxy_file.open(encoding="utf-8") as f:
    galaxy = yaml.safe_load(f)

version = galaxy["version"]

version_file.write_text(
    f'__version__ = "{version}"\n',
    encoding="utf-8",
)

print(f"Generated version: {version}")
