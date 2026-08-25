//! Static, side-effect-free shell completion for `iicp-node`.
use std::collections::BTreeSet;
const COMMANDS: &[&str] = &[
    "completion",
    "config",
    "credits",
    "doctor",
    "healthcheck",
    "help",
    "init",
    "list",
    "mcp-gateway",
    "operator",
    "proxy",
    "query",
    "serve",
    "service",
    "update",
];
pub fn candidates(tokens: &[String]) -> Vec<&'static str> {
    if tokens.is_empty() {
        return COMMANDS.to_vec();
    }
    let partial = tokens.last().map(String::as_str).unwrap_or("");
    let prior = &tokens[..tokens.len() - 1];
    let command = prior.first().map(String::as_str).unwrap_or("");
    let values: &[&str] = match (command, prior.last().map(String::as_str)) {
        ("query", Some("--routing-profile")) => {
            &["eu-restricted", "sensitive", "standard", "strict-policy"]
        }
        ("serve", Some("--backend-type")) => {
            &["anthropic", "llamacpp", "meshllm", "openai_compat", "vllm"]
        }
        _ => &[],
    };
    if !values.is_empty() {
        return values
            .iter()
            .copied()
            .filter(|v| v.starts_with(partial))
            .collect();
    }
    let path: Vec<&str> = prior
        .iter()
        .map(String::as_str)
        .filter(|v| !v.is_empty() && !v.starts_with('-'))
        .collect();
    let choices: &[&str] = if partial.starts_with('-') {
        match command {
            "query" => &[
                "--directory-url",
                "--intent",
                "--json",
                "--node",
                "--routing-profile",
            ],
            "serve" => &[
                "--backend-type",
                "--directory-url",
                "--host",
                "--node",
                "--port",
                "--routing-profile",
            ],
            _ => &["--help", "--version"],
        }
    } else {
        match path.as_slice() {
            [] => COMMANDS,
            ["operator"] => &["decrypt", "dsr", "encrypt", "key", "rename"],
            ["operator", "dsr"] => &["anonymize", "export", "restrict"],
            ["operator", "key"] => &["export", "generate", "import", "list", "revoke", "rotate"],
            ["service"] => &["install", "restart", "status", "uninstall"],
            ["config"] => &[
                "effective",
                "migrate-node",
                "migrate-node-secrets",
                "schema",
                "validate",
                "wizard",
            ],
            _ => &[],
        }
    };
    choices
        .iter()
        .copied()
        .filter(|v| v.starts_with(partial))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
pub fn script(input: &str) -> Result<String, String> {
    let shell = if input == "pwsh" { "powershell" } else { input };
    let value = match shell {
        "bash" => r#"_iicp_node_complete() {
  COMPREPLY=()
  local -a args=("${COMP_WORDS[@]:1:$COMP_CWORD}")
  while IFS= read -r candidate; do COMPREPLY+=("$candidate"); done < <(command iicp-node __complete "${args[@]}")
}
complete -F _iicp_node_complete iicp-node
"#,
        "zsh" => r#"_iicp_node_complete() {
  local -a args candidates
  args=("${words[@]:1}")
  candidates=("${(@f)$(command iicp-node __complete "${args[@]}")}")
  compadd -- $candidates
}
compdef _iicp_node_complete iicp-node
"#,
        "fish" => "function __iicp_node_complete\n  set -l tokens (commandline -opc)\n  set -e tokens[1]\n  set -a tokens (commandline -ct)\n  command iicp-node __complete $tokens\nend\ncomplete -c iicp-node -f -a '(__iicp_node_complete)'\n",
        "powershell" => "Register-ArgumentCompleter -Native -CommandName iicp-node -ScriptBlock {\n  param($wordToComplete, $commandAst, $cursorPosition)\n  $tokens = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })\n  if ($tokens.Count -eq 0 -or $commandAst.Extent.Text.EndsWith(' ')) { $tokens += '' }\n  iicp-node __complete @tokens | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n}\n",
        _ => return Err(format!("unsupported shell: {input}")),
    };
    Ok(value.into())
}
