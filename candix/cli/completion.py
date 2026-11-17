"""Shell completion generation for bash, zsh and fish."""

from __future__ import annotations

from typing import Iterable

COMMANDS = (
    "scan",
    "exploit",
    "report",
    "authorize",
    "detectors",
    "payloads",
    "lab",
    "fuzz",
    "tui",
    "doctor",
    "config",
    "compare",
    "api",
    "notify",
    "playbooks",
    "shell",
    "version",
)

GLOBAL_OPTIONS = (
    "--help",
    "--version",
    "--config",
    "--profile",
    "--set",
    "--quiet",
    "--verbose",
    "--json",
    "--log-file",
    "--log-level",
)

COMMAND_OPTIONS: dict[str, tuple[str, ...]] = {
    "scan": (
        "--engagement",
        "--authorized",
        "--exploit",
        "--formats",
        "--out",
        "--max-rps",
        "--concurrency",
        "--max-pages",
        "--max-endpoints",
        "--detectors",
        "--categories",
        "--min-severity",
        "--no-crawl",
        "--no-discover",
        "--archive",
        "--fail-on",
        "--artifacts",
        "--header",
        "--cookie",
        "--proxy",
        "--timeout",
    ),
    "exploit": ("--engagement", "--authorized", "--max-proofs", "--techniques", "--out", "--formats"),
    "report": ("--formats", "--out", "--min-severity", "--title", "--archive", "--no-evidence", "--compare"),
    "authorize": ("--engagement", "--client", "--operator", "--by", "--include", "--exclude", "--expires-in-days", "--allow-exploit", "--max-rps", "--out"),
    "fuzz": ("--engagement", "--authorized", "--iterations", "--strategy", "--seed", "--param", "--save-corpus", "--stop-on-finding"),
    "lab": ("--host", "--port", "--scan", "--serve", "--formats", "--out", "--max-proofs"),
    "tui": ("--engagement", "--authorized", "--exploit", "--max-proofs"),
    "api": ("--host", "--port", "--token", "--allow-anonymous", "--artifacts", "--cors-origin"),
    "notify": ("--integration", "--endpoint", "--token", "--secret", "--project", "--link", "--siem-format", "--min-severity"),
    "compare": ("--json", "--out"),
    "playbooks": ("--for-report", "--json"),
    "detectors": ("--category", "--json", "--verbose"),
    "payloads": ("--limit", "--json"),
    "config": ("--config", "--profile", "--section", "--json"),
    "doctor": ("--json",),
    "shell": ("--authorized",),
    "version": ("--json",),
}


def bash_completion(program: str = "candix") -> str:
    lines = [
        f"_{program}_completions() {{",
        "  local cur prev cmd",
        "  COMPREPLY=()",
        '  cur="${COMP_WORDS[COMP_CWORD]}"',
        '  prev="${COMP_WORDS[COMP_CWORD-1]}"',
        "  cmd=\"${COMP_WORDS[1]}\"",
        "  if [[ $COMP_CWORD -eq 1 ]]; then",
        f'    COMPREPLY=( $(compgen -W "{" ".join(COMMANDS)}" -- "$cur") )',
        "    return 0",
        "  fi",
        "  case \"$cmd\" in",
    ]
    for command, options in COMMAND_OPTIONS.items():
        joined = " ".join(options + ("--help",))
        lines.append(f'    {command}) COMPREPLY=( $(compgen -W "{joined}" -- "$cur") ) ;;')
    lines.extend(
        [
            "    *) COMPREPLY=( $(compgen -W \"--help --version\" -- \"$cur\") ) ;;",
            "  esac",
            "  return 0",
            "}",
            f"complete -F _{program}_completions {program}",
            "",
        ]
    )
    return "\n".join(lines)


def zsh_completion(program: str = "candix") -> str:
    lines = [
        f"#compdef {program}",
        "",
        f"_{program}() {{",
        "  local -a commands",
        "  commands=(",
    ]
    for command in COMMANDS:
        lines.append(f"    '{command}:{_describe_command(command)}'")
    lines.extend(["  )", "  _arguments -C \\", "    '1:command:->command' \\", "    '*::arg:->args'", "  case $state in", "    command) _describe 'command' commands ;;", "    args)  _arguments \\"])
    for options in sorted({option for values in COMMAND_OPTIONS.values() for option in values}):
        lines.append(f"      '{options}[option]' \\")
    lines.extend(["      ;;", "  esac", "}", "", f"_{program} \"$@\"", ""])
    return "\n".join(lines)


def fish_completion(program: str = "candix") -> str:
    lines = []
    for command, options in COMMAND_OPTIONS.items():
        lines.append(f"complete -c {program} -f -n '__fish_use_subcommand' -a {command} -d '{_describe_command(command)}'")
        for option in options:
            name = option.lstrip("-")
            lines.append(f"complete -c {program} -f -n '__fish_seen_subcommand_from {command}' -l {name}")
    return "\n".join(lines) + "\n"


def powershell_completion(program: str = "candix") -> str:
    commands = ", ".join(f"'{command}'" for command in COMMANDS)
    return "\n".join(
        [
            f"Register-ArgumentCompleter -Native -CommandName {program} -ScriptBlock {{",
            "    param($wordToComplete, $commandAst, $cursorPosition)",
            f"    $commands = @({commands})",
            "    $commands | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {",
            "        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)",
            "    }",
            "}",
            "",
        ]
    )


def _describe_command(command: str) -> str:
    descriptions = {
        "scan": "recon, detect and report findings",
        "exploit": "detect and exploit with proofs",
        "report": "render reports from saved scans",
        "authorize": "create an authorization document",
        "detectors": "list detectors",
        "payloads": "inspect the payload catalogue",
        "lab": "run the vulnerable lab",
        "fuzz": "mutation fuzzing",
        "tui": "terminal dashboard",
        "doctor": "environment checks",
        "config": "show configuration",
        "compare": "compare two scans",
        "api": "serve the HTTP API",
        "notify": "send reports to integrations",
        "playbooks": "exploitation playbooks",
        "shell": "interactive shell",
        "version": "print version",
    }
    return descriptions.get(command, command)


GENERATORS = {
    "bash": bash_completion,
    "zsh": zsh_completion,
    "fish": fish_completion,
    "powershell": powershell_completion,
}


def generate(shell: str, program: str = "candix") -> str:
    generator = GENERATORS.get(shell.lower())
    if generator is None:
        raise ValueError(f"unsupported shell: {shell}")
    return generator(program)


def complete(word: str, *, command: str = "") -> list[str]:
    """Programmatic completion used by the shell and tests."""

    pool: Iterable[str]
    if not command:
        pool = COMMANDS
    else:
        pool = COMMAND_OPTIONS.get(command, GLOBAL_OPTIONS)
    return sorted(item for item in pool if item.startswith(word))
