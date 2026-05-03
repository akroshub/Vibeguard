import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("vibeguard")


@dataclass
class RemediationConfig:
    """Configuration passed to all remediation functions."""
    dry_run: bool = False


def print_alert(filepath: str, secret_type: str, line_number: int) -> None:
    """Print a loud, structured security threat warning to the console."""
    print("\n" + "╔" + "═" * 54 + "╗")
    print("║  🚨  VIBEGUARD — SECURITY THREAT DETECTED            ║")
    print("╠" + "═" * 54 + "╣")
    print(f"║  File     : {filepath[:46].ljust(46)}  ║")
    print(f"║  Type     : {secret_type[:46].ljust(46)}  ║")
    print(f"║  Line     : {str(line_number)[:46].ljust(46)}  ║")
    print("║  Action   : Auto-remediating now...                  ║")
    print("╚" + "═" * 54 + "╝\n")


def _env_var_replacement(env_var_name: str, file_ext: str) -> str:
    """Return the language-appropriate environment variable reference."""
    if file_ext in {".js", ".ts", ".jsx", ".tsx"}:
        return f"process.env.{env_var_name}"
    return f'os.environ.get("{env_var_name}")'


def _ensure_os_import(content: str, file_ext: str) -> str:
    """Add 'import os' to Python files if not already present."""
    if file_ext != ".py":
        return content
    if "import os" in content:
        return content
    return "import os\n" + content


def rewrite_source_file(filepath: str, secret_value: str, env_var_name: str, config: RemediationConfig) -> bool:
    """Replace the raw secret in the source file with an env var reference."""
    path = Path(filepath)
    file_ext = path.suffix.lower()
    replacement = _env_var_replacement(env_var_name, file_ext)

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Cannot read {filepath} — {e}")
        return False

    if secret_value not in content:
        return False

    new_content = content.replace(secret_value, replacement)
    new_content = _ensure_os_import(new_content, file_ext)

    if config.dry_run:
        logger.info(f"[DRY RUN] Would rewrite {filepath}")
        return True

    tmp_path = path.with_suffix(path.suffix + ".vibeguard.tmp")
    try:
        tmp_path.write_text(new_content, encoding="utf-8")
        os.replace(tmp_path, path)
        return True
    except OSError as e:
        logger.error(f"Failed to write {filepath} — {e}")
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        return False


def update_env_file(project_root: str, env_var_name: str, config: RemediationConfig) -> None:
    """Create or append to .env file. Never overwrites existing entries."""
    env_path = Path(project_root) / ".env"
    entry = f"{env_var_name}=REPLACE_WITH_YOUR_ACTUAL_KEY"

    if config.dry_run:
        logger.info(f"[DRY RUN] Would write {entry} to .env")
        return

    try:
        if env_path.exists():
            existing = env_path.read_text(encoding="utf-8")
            if env_var_name in existing:
                return
            with env_path.open("a", encoding="utf-8") as f:
                f.write(f"\n{entry}\n")
        else:
            with env_path.open("w", encoding="utf-8") as f:
                f.write("# .env — managed by VibeGuard\n")
                f.write("# Replace placeholder values with your real keys.\n")
                f.write("# DO NOT commit this file to git.\n\n")
                f.write(f"{entry}\n")
    except OSError as e:
        logger.error(f"Failed to update .env — {e}")


def update_gitignore(project_root: str, config: RemediationConfig) -> None:
    """Ensure .env is listed in .gitignore."""
    gitignore_path = Path(project_root) / ".gitignore"
    addition = "\n# Added by VibeGuard — prevent secret leaks\n.env\n.env.*\n!.env.example\n"

    if config.dry_run:
        logger.info("[DRY RUN] Would patch .gitignore")
        return

    try:
        if gitignore_path.exists():
            content = gitignore_path.read_text(encoding="utf-8")
            if ".env" in [l.strip() for l in content.splitlines()]:
                return
            with gitignore_path.open("a", encoding="utf-8") as f:
                f.write(addition)
        else:
            gitignore_path.write_text(addition.lstrip(), encoding="utf-8")
        print("✅ .gitignore updated — .env is now protected")
    except OSError as e:
        logger.error(f"Failed to update .gitignore — {e}")


def print_remediation_report(filepath: str) -> None:
    """Print a summary after successful remediation."""
    print("✅ REMEDIATION COMPLETE")
    print(f"   Secret removed from : {filepath}")
    print(f"   Saved to            : .env")
    print(f"   Protected by        : .gitignore")
    print(f"   Next step           : Set the real value in your .env file\n")


def remediate(filepath, line_number, secret_value, pattern_name, env_var_name, description, project_root, config):
    """Full remediation pipeline: Alert → Rewrite → .env → .gitignore → Report."""
    print_alert(filepath, description, line_number)
    ok = rewrite_source_file(filepath, secret_value, env_var_name, config)
    if not ok and not config.dry_run:
        return
    update_env_file(project_root, env_var_name, config)
    update_gitignore(project_root, config)
    if not config.dry_run:
        print_remediation_report(filepath)
