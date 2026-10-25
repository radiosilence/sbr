//! `sbr rule-set compile|decompile|match|format`, mirroring
//! `sing-box rule-set …`. Output of `compile` is a plain static file: serve
//! it from any web server you control and point a `remote` rule-set at it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use sbr_engine::sbr_config::srs::{self, PlainRuleSet};
use sbr_engine::sbr_config::{Options, RuleSetFormat};
use sbr_engine::sbr_core::router::Router;
use sbr_engine::sbr_core::{Destination, Metadata, Network};

#[derive(Subcommand)]
pub enum RuleSetCmd {
    /// Compile rule-set json to binary
    Compile {
        /// Source path, or `stdin`
        source: PathBuf,
        /// Output file (default: <file_name>.srs)
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// Decompile rule-set binary to json
    Decompile {
        /// Binary path, or `stdin`
        source: PathBuf,
        /// Output file (default: <file_name>.json)
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// Check if an IP address or a domain matches the rule-set
    Match {
        /// Rule-set path, or `stdin`
        path: PathBuf,
        /// IP address or domain
        target: String,
        /// rule-set format: source or binary
        #[arg(short = 'f', long = "format", default_value = "source")]
        format: String,
    },
    /// Format rule-set json
    Format {
        /// Source path, or `stdin`
        source: PathBuf,
        /// Write result to (source) file instead of stdout
        #[arg(short = 'w', long = "write")]
        write: bool,
    },
}

fn read_input(p: &Path) -> Result<Vec<u8>> {
    if p == Path::new("stdin") {
        let mut v = Vec::new();
        std::io::stdin().read_to_end(&mut v)?;
        Ok(v)
    } else {
        std::fs::read(p).with_context(|| format!("read {}", p.display()))
    }
}

fn with_ext(p: &Path, strip: &str, add: &str) -> PathBuf {
    let s = p.to_string_lossy();
    PathBuf::from(match s.strip_suffix(strip) {
        Some(base) => format!("{base}{add}"),
        None => format!("{s}{add}"),
    })
}

/// Write via a temp file so a failed run never leaves a truncated output.
fn write_output(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = with_ext(path, "", ".tmp");
    std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))
}

pub fn run(cmd: RuleSetCmd) -> Result<()> {
    match cmd {
        RuleSetCmd::Compile { source, output } => {
            let text = String::from_utf8(read_input(&source)?).context("source is not UTF-8")?;
            let mut set = PlainRuleSet::from_json(&text)?;
            set.downgrade_version();
            let out = output.unwrap_or_else(|| with_ext(&source, ".json", ".srs"));
            write_output(&out, &set.write()?)
        }
        RuleSetCmd::Decompile { source, output } => {
            let set = srs::read(&read_input(&source)?)?;
            if set.has_adguard() {
                bail!("unable to decompile binary AdGuard rules to rule-set.");
            }
            let out = output.unwrap_or_else(|| with_ext(&source, ".srs", ".json"));
            write_output(&out, set.to_json_pretty().as_bytes())
        }
        RuleSetCmd::Format { source, write } => {
            let input = read_input(&source)?;
            let set = PlainRuleSet::from_json(std::str::from_utf8(&input).context("source is not UTF-8")?)?;
            let out = set.to_json_pretty();
            if !write || source == Path::new("stdin") {
                std::io::stdout().write_all(out.as_bytes())?;
                println!();
            } else if out.as_bytes() != input {
                write_output(&source, out.as_bytes())?;
                eprintln!("{}", std::fs::canonicalize(&source)?.display());
            }
            Ok(())
        }
        RuleSetCmd::Match { path, target, format } => {
            let data = read_input(&path)?;
            let format = match format.as_str() {
                "source" => RuleSetFormat::Source,
                "binary" => RuleSetFormat::Binary,
                f => bail!("unknown rule-set format: {f}"),
            };
            let rules = sbr_engine::sbr_config::parse_rule_set(&data, format)?;
            // One route rule per headless rule, so the router reports which matched.
            let mut wrapped = Vec::new();
            for i in 0..rules.len() {
                wrapped.push(format!(r#"{{"rule_set":"s{i}","outbound":"o"}}"#));
            }
            let sets: Vec<String> = (0..rules.len())
                .map(|i| format!(r#"{{"type":"inline","tag":"s{i}","rules":[]}}"#))
                .collect();
            let o = Options::parse(&format!(
                r#"{{"outbounds":[{{"type":"block","tag":"none"}},{{"type":"direct","tag":"o"}}],"route":{{"rules":[{}],"rule_set":[{}],"final":"none"}}}}"#,
                wrapped.join(","),
                sets.join(",")
            ))?;
            let tags = ["none", "o"];
            let router = Router::new(
                &o.route.rules,
                &o.route.rule_sets,
                o.final_outbound(),
                |t| tags.iter().position(|x| *x == t),
                |_| Err(std::io::ErrorKind::NotFound.into()),
            )?;
            for (i, r) in rules.iter().enumerate() {
                router.update_rule_set(&format!("s{i}"), std::slice::from_ref(r))?;
            }
            let meta = Metadata::new(
                "".into(),
                "",
                Network::Tcp,
                "0.0.0.0:0".parse().unwrap(),
                Destination::from_host_port(&target, 0),
            );
            let mut from = 0;
            while let Some((i, _)) = router.next(&meta, from) {
                let info = sbr_engine::sbr_core::router::RuleInfo::new(&rules[i]);
                println!("match rules.[{i}]: {}", info.payload);
                from = i + 1;
            }
            Ok(())
        }
    }
}
