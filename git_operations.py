#!/usr/bin/env python3
import subprocess
import os

os.chdir(r'C:\Users\Saar\fireWTwall')

try:
    # Add all changes
    print("Adding changes...")
    subprocess.run(['git', 'add', '-A'], check=True)
    
    # Commit with message
    commit_message = """Add Bun package support

- Add bunfig.toml with Bun configuration
- Update nodejs/package.json to include Bun runtime and scripts
- Add docs/nodejs/bun.md with complete Bun documentation
- Update README.md with Bun badges and installation instructions
- Update docs/index.md to reference Bun support
- Update docs/nodejs/installation.md with Bun installation instructions

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"""
    
    print("Committing...")
    subprocess.run(['git', 'commit', '-m', commit_message], check=True)
    
    # Push to remote
    print("Pushing...")
    subprocess.run(['git', 'push'], check=True)
    
    print("✅ All operations completed successfully!")
    
except subprocess.CalledProcessError as e:
    print(f"❌ Error: {e}")
    exit(1)
