#!/usr/bin/env python3
"""
MadaraMaster — Git Deploy Automation
======================================
Automates repository initialization and push to GitHub.

Usage:  python deploy.py
"""

import os
import sys
import subprocess


def run_cmd(cmd: list, cwd: str = ".") -> bool:
    """Runs a shell command and returns True on success."""
    print(f"  ▸ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    ✗ Error: {result.stderr.strip()}")
        return False
    if result.stdout.strip():
        print(f"    {result.stdout.strip()}")
    return True


def main():
    print("=" * 60)
    print("  🧹 MadaraMaster — Git Deploy Automation")
    print("=" * 60)
    print()

    # Check git
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("✗ Error: Git is not installed or not in PATH.")
        sys.exit(1)

    project_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"  Project directory: {project_dir}")
    print()

    # Step 1: Initialize
    print("[1/6] Initializing Git repository...")
    if os.path.exists(os.path.join(project_dir, ".git")):
        print("  ℹ Repository already initialized.")
    else:
        if not run_cmd(["git", "init"], cwd=project_dir):
            sys.exit(1)

    # Step 2: .gitignore
    gitignore_path = os.path.join(project_dir, ".gitignore")
    if not os.path.exists(gitignore_path):
        print("[2/6] Creating .gitignore...")
        with open(gitignore_path, "w") as f:
            f.write(
                "# Python\n"
                "__pycache__/\n"
                "*.pyc\n"
                "*.pyo\n"
                ".pytest_cache/\n"
                "*.egg-info/\n"
                "dist/\n"
                "build/\n"
                "\n"
                "# IDE\n"
                ".vscode/\n"
                ".idea/\n"
                "\n"
                "# Environment\n"
                ".env\n"
                "venv/\n"
                ".venv/\n"
                "\n"
                "# Test sandbox\n"
                "sandbox/\n"
            )
    else:
        print("[2/6] .gitignore already exists.")

    # Step 3: Stage
    print("[3/6] Staging all files...")
    if not run_cmd(["git", "add", "."], cwd=project_dir):
        sys.exit(1)

    # Step 4: Commit
    print("[4/6] Creating initial commit...")
    if not run_cmd(
        ["git", "commit", "-m", "🧹 Initial commit — MadaraMaster v2.1.0"],
        cwd=project_dir,
    ):
        print("  ℹ If commit failed, files may already be committed.")

    # Step 5: Branch
    print("[5/6] Setting branch to 'main'...")
    run_cmd(["git", "branch", "-M", "main"], cwd=project_dir)

    # Step 6: Remote + push
    print("[6/6] Adding remote origin...")
    remote_url = input(
        "\n  🔗 Enter the GitHub remote URL (e.g. https://github.com/user/repo.git): "
    ).strip()

    if not remote_url:
        print("  ✗ No URL provided. Skipping remote setup.")
        print("\n  You can add it manually later:")
        print("    git remote add origin <URL>")
        print("    git push -u origin main")
    else:
        run_cmd(["git", "remote", "remove", "origin"], cwd=project_dir)
        if not run_cmd(["git", "remote", "add", "origin", remote_url], cwd=project_dir):
            sys.exit(1)

        print("\n  Pushing to remote...")
        if run_cmd(["git", "push", "-u", "origin", "main"], cwd=project_dir):
            print("\n  ✔ Successfully pushed to remote!")
        else:
            print("\n  ✗ Push failed. Check your credentials and remote URL.")
            print("    Try: git push -u origin main")

    print()
    print("=" * 60)
    print("  ✔ Deployment complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
