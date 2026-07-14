#!/usr/bin/env python3
"""Detect applicable security-review profiles without executing repository code."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


SKIP_DIRS = {
    ".git", ".hg", ".svn", ".next", ".nuxt", ".svelte-kit", ".terraform",
    ".tox", ".venv", "venv", "node_modules", "vendor", "dist", "build",
    "coverage", "target", "Pods", "DerivedData", "__pycache__",
}
TEXT_NAMES = {
    "package.json", "pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pom.xml", "build.gradle",
    "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "serverless.yml",
    "serverless.yaml", "template.yaml", "template.yml", "samconfig.toml",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile.lock",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "gradle.lockfile", "Podfile", "Podfile.lock", "Package.swift", "Package.resolved",
}
AI_TOKENS = {
    "openai", "anthropic", "langchain", "langgraph", "llamaindex", "llama-index",
    "semantic-kernel", "autogen", "crewai", "google-generativeai", "transformers",
    "bedrock-runtime", "mistralai", "cohere",
}
WEB_TOKENS = {
    "express", "fastify", "koa", "hapi", "next", "nuxt", "sveltekit", "react",
    "angular", "vue", "django", "flask", "fastapi", "starlette", "rails", "sinatra",
    "spring-boot", "aspnet", "gin-gonic", "actix-web",
}
API_TOKENS = {"openapi", "swagger", "graphql", "apollo-server", "express", "fastify", "koa", "hapi", "fastapi", "grpc"}
AGENT_TOKENS = {"langgraph", "autogen", "crewai", "mcp", "model-context-protocol"}


def add(evidence: dict[str, list[dict[str, str]]], profile: str, path: str, reason: str) -> None:
    item = {"path": path, "reason": reason}
    if item not in evidence.setdefault(profile, []):
        evidence[profile].append(item)


def bounded_text(path: Path, limit: int = 1_000_000) -> str:
    try:
        if path.stat().st_size > limit or path.is_symlink():
            return ""
        return path.read_text(encoding="utf-8", errors="ignore").lower()
    except (OSError, UnicodeError):
        return ""


def walk(root: Path, max_files: int) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    warnings: list[str] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not Path(current, d).is_symlink())
        for name in sorted(names):
            path = Path(current, name)
            if path.is_symlink() or not path.is_file():
                continue
            files.append(path)
            if len(files) >= max_files:
                warnings.append(f"file limit {max_files} reached; detection may be incomplete")
                return files, warnings
    return files, warnings


def detect(root: Path, max_files: int) -> dict[str, object]:
    files, warnings = walk(root, max_files)
    evidence: dict[str, list[dict[str, str]]] = {"core": [{"path": ".", "reason": "universal software security baseline"}]}

    for path in files:
        rel = path.relative_to(root).as_posix()
        name = path.name
        lower_name = name.lower()
        lower_rel = rel.lower()

        if name in MANIFEST_NAMES:
            add(evidence, "supply-chain", rel, "dependency or lock manifest")
        if lower_name == "dockerfile" or lower_name.startswith("dockerfile.") or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            add(evidence, "containers", rel, "container build or runtime configuration")
        if lower_rel.startswith(".github/workflows/") or lower_rel.startswith(".gitlab-ci") or lower_name in {"jenkinsfile", "azure-pipelines.yml", "azure-pipelines.yaml", "bitbucket-pipelines.yml", "circle.yml"} or lower_rel.startswith(".circleci/"):
            add(evidence, "cicd", rel, "CI/CD workflow configuration")
        if path.suffix.lower() == ".tf" or lower_name in {"pulumi.yaml", "pulumi.yml", "cdk.json", "bicepconfig.json"} or path.suffix.lower() == ".bicep":
            add(evidence, "cloud-iac", rel, "infrastructure-as-code configuration")
        if lower_name in {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"} or path.suffix.lower() in {".graphql", ".gql", ".proto"}:
            add(evidence, "api", rel, "API schema or protocol definition")
        if lower_name in {"serverless.yml", "serverless.yaml", "samconfig.toml"} or lower_name.startswith("template.") and path.suffix.lower() in {".yaml", ".yml"}:
            text = bounded_text(path)
            if "serverless" in text or "aws::serverless" in text or lower_name.startswith("serverless") or lower_name == "samconfig.toml":
                add(evidence, "serverless", rel, "serverless deployment configuration")
        if ".xcodeproj/" in lower_rel or ".xcworkspace/" in lower_rel or lower_name in {"androidmanifest.xml", "podfile", "package.swift"} or "src/main/androidmanifest.xml" in lower_rel:
            add(evidence, "mobile", rel, "mobile project configuration")
        if lower_name in {"skill.md", "mcp.json"} or lower_rel.startswith(".claude/") or lower_rel.startswith(".codex/") or lower_rel.startswith("agents/"):
            add(evidence, "agentic", rel, "agent or reusable skill configuration")

        should_read = name in TEXT_NAMES or (path.suffix.lower() in {".json", ".toml", ".yaml", ".yml"} and path.stat().st_size <= 200_000)
        if should_read:
            text = bounded_text(path)
            for token in sorted(AI_TOKENS):
                if token in text:
                    add(evidence, "ai-llm", rel, f"AI/LLM dependency or configuration token: {token}")
                    break
            for token in sorted(AGENT_TOKENS):
                if token in text:
                    add(evidence, "agentic", rel, f"agentic dependency or configuration token: {token}")
                    break
            for token in sorted(WEB_TOKENS):
                if token in text:
                    add(evidence, "web", rel, f"web framework token: {token}")
                    break
            for token in sorted(API_TOKENS):
                if token in text:
                    add(evidence, "api", rel, f"API framework or schema token: {token}")
                    break
            if "kind:" in text and "apiversion:" in text and any(k in text for k in ("deployment", "statefulset", "daemonset", "clusterrole", "networkpolicy", "service")):
                add(evidence, "kubernetes", rel, "Kubernetes resource manifest")

    ordered = {profile: sorted(items, key=lambda x: (x["path"], x["reason"])) for profile, items in sorted(evidence.items())}
    return {
        "schema_version": "1.0",
        "root": str(root),
        "profiles": sorted(ordered),
        "evidence": ordered,
        "warnings": warnings,
        "files_considered": len(files),
        "execution_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", nargs="?", default=".")
    parser.add_argument("--max-files", type=int, default=50_000)
    args = parser.parse_args()
    root = Path(args.repository).expanduser().resolve()
    if not root.is_dir():
        print(f"error: repository is not a directory: {root}", file=sys.stderr)
        return 2
    if args.max_files < 1:
        print("error: --max-files must be positive", file=sys.stderr)
        return 2
    print(json.dumps(detect(root, args.max_files), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
