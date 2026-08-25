use iicp_client::cli_completion::{candidates, script};
#[test]
fn static_candidates_cover_contract() {
    for (tokens, wanted) in [
        (vec![], vec!["completion", "init", "query", "serve"]),
        (vec!["op"], vec!["operator"]),
        (
            vec!["operator", ""],
            vec!["decrypt", "dsr", "encrypt", "key", "rename"],
        ),
        (
            vec!["operator", "dsr", ""],
            vec!["anonymize", "export", "restrict"],
        ),
        (
            vec!["service", ""],
            vec!["install", "restart", "status", "uninstall"],
        ),
        (
            vec!["query", "--routing-profile", ""],
            vec!["eu-restricted", "sensitive", "standard", "strict-policy"],
        ),
        (
            vec!["serve", "--backend-type", ""],
            vec!["anthropic", "llamacpp", "meshllm", "openai_compat", "vllm"],
        ),
        (vec!["query", "--rou"], vec!["--routing-profile"]),
    ] {
        let t = tokens.into_iter().map(String::from).collect::<Vec<_>>();
        let got = candidates(&t);
        for value in wanted {
            assert!(got.contains(&value), "missing {value}");
        }
    }
}
#[test]
fn scripts_are_static() {
    for shell in ["bash", "zsh", "fish", "powershell", "pwsh"] {
        assert!(script(shell).unwrap().contains("iicp-node __complete"));
    }
}
