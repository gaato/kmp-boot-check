use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Ok,
    Warning,
    BootRisk,
    Unknown,
}

impl Severity {
    pub fn status(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warn",
            Self::BootRisk => "risk",
            Self::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warning => "WARN",
            Self::BootRisk => "RISK",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kernel {
    pub uname: String,
    pub package: String,
    pub install_time: u64,
    pub running: bool,
    pub latest: bool,
    pub next_boot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModulePolicy {
    pub name: String,
    pub module: String,
    pub enabled: bool,
    pub initrd: InitrdPolicy,
    pub severity: Severity,
    pub reason: String,
    pub kernel_scope: KernelScope,
    pub source: PolicySource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KmpModule {
    pub package: String,
    pub module: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootFilesystem {
    pub fstype: String,
    pub initrd_required: bool,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitrdPolicy {
    Optional,
    Required,
    Auto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelScope {
    NextBoot,
    Important,
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextBootHint {
    pub source: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySource {
    AutoKmp,
    BootFilesystemKmp,
    Config,
}

impl PolicySource {
    pub fn label(self) -> &'static str {
        match self {
            Self::AutoKmp => "auto-kmp",
            Self::BootFilesystemKmp => "boot-fs-kmp",
            Self::Config => "config",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleResult {
    pub policy: ModulePolicy,
    pub module_found: bool,
    pub initrd_found: Option<bool>,
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelResult {
    pub kernel: Kernel,
    pub module_results: Vec<ModuleResult>,
}

impl KernelResult {
    pub fn severity(&self) -> Severity {
        self.module_results
            .iter()
            .map(|item| item.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub kernels: Vec<KernelResult>,
    pub diagnostics: Vec<String>,
}

impl CheckResult {
    pub fn severity(&self) -> Severity {
        let mut severity = self
            .kernels
            .iter()
            .map(KernelResult::severity)
            .max()
            .unwrap_or(Severity::Ok);
        if !self.diagnostics.is_empty() {
            severity = severity.max(Severity::Unknown);
        }
        severity
    }
}

pub trait SystemProbe {
    fn installed_kernels(&self) -> Vec<Kernel>;
    fn installed_kmp_modules(&self) -> Vec<KmpModule>;
    fn running_kernel(&self) -> String;
    fn next_boot_kernel_hint(&self) -> Option<NextBootHint>;
    fn root_fstype(&self) -> String;
    fn boot_filesystems(&self) -> Vec<BootFilesystem>;
    fn has_installed_package(&self, patterns: &[String]) -> bool;
    fn has_module(&self, kernel: &str, module: &str) -> bool;
    fn initrd_has_module(&self, kernel: &str, module: &str) -> Option<bool>;
}

#[derive(Default)]
pub struct RealSystemProbe;

impl SystemProbe for RealSystemProbe {
    fn installed_kernels(&self) -> Vec<Kernel> {
        let output = run_output(
            "rpm",
            &[
                "-qa",
                "kernel-*",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME}\n",
            ],
        );
        let Some(output) = output else {
            return Vec::new();
        };

        let mut kernels = Vec::new();
        let mut seen = HashSet::new();
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            let Some((package, install_time_raw)) = line.split_once('\t') else {
                continue;
            };
            let install_time = install_time_raw.trim().parse::<u64>().unwrap_or(0);
            let Some(provides) = run_output("rpm", &["-q", "--provides", package]) else {
                continue;
            };
            for provide in provides.lines() {
                let Some(uname) = provide.trim().strip_prefix("kernel-uname-r = ") else {
                    continue;
                };
                if uname == "vmlinux" || !seen.insert(uname.to_string()) {
                    continue;
                }
                kernels.push(Kernel {
                    uname: uname.to_string(),
                    package: package.to_string(),
                    install_time,
                    running: false,
                    latest: false,
                    next_boot: false,
                });
            }
        }

        kernels.sort_by(|a, b| {
            a.install_time
                .cmp(&b.install_time)
                .then_with(|| a.uname.cmp(&b.uname))
        });
        kernels
    }

    fn installed_kmp_modules(&self) -> Vec<KmpModule> {
        let output = run_output(
            "rpm",
            &[
                "-qa",
                "*-kmp-*",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n",
            ],
        );
        let Some(output) = output else {
            return Vec::new();
        };

        let mut modules = Vec::new();
        let mut seen = HashSet::new();
        for package in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let Some(provides) = run_output("rpm", &["-q", "--provides", package]) else {
                continue;
            };
            for provide in provides.lines() {
                let Some(module) = parse_kmod_provide(provide.trim()) else {
                    continue;
                };
                let key = (package.to_string(), module.clone());
                if !seen.insert(key) {
                    continue;
                }
                modules.push(KmpModule {
                    package: package.to_string(),
                    module,
                });
            }
        }
        modules.sort_by(|a, b| {
            a.package
                .cmp(&b.package)
                .then_with(|| a.module.cmp(&b.module))
        });
        modules
    }

    fn running_kernel(&self) -> String {
        run_output("uname", &["-r"])
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    }

    fn next_boot_kernel_hint(&self) -> Option<NextBootHint> {
        if let Some(value) = run_output("sdbootutil", &["get-default"]) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(NextBootHint {
                    source: "sdbootutil get-default".to_string(),
                    value: value.to_string(),
                });
            }
        }

        if let Some(output) = run_output("bootctl", &["list", "--json=short", "--no-pager"])
            && let Some(value) = extract_bootctl_default_entry(&output)
        {
            return Some(NextBootHint {
                source: "bootctl list --json=short".to_string(),
                value,
            });
        }

        let output = run_output_any_status("bootctl", &["status", "--no-pager"])?;
        extract_bootctl_status_default_entry(&output).map(|value| NextBootHint {
            source: "bootctl status".to_string(),
            value,
        })
    }

    fn root_fstype(&self) -> String {
        run_output("findmnt", &["-no", "FSTYPE", "/"])
            .and_then(|value| value.lines().next().map(|line| line.trim().to_string()))
            .unwrap_or_default()
    }

    fn boot_filesystems(&self) -> Vec<BootFilesystem> {
        let mut filesystems = Vec::new();
        let root_fstype = self.root_fstype();
        if !root_fstype.is_empty() {
            filesystems.push(BootFilesystem {
                fstype: root_fstype,
                initrd_required: true,
                reason: "/ is a boot-required mount".to_string(),
            });
        }

        let Some(output) = run_output(
            "findmnt",
            &[
                "--fstab",
                "--noheadings",
                "--raw",
                "--output",
                "FSTYPE,OPTIONS,TARGET",
            ],
        ) else {
            return filesystems;
        };

        let mut seen = filesystems
            .iter()
            .map(|filesystem| filesystem.fstype.clone())
            .collect::<HashSet<_>>();
        for line in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let mut fields = line.split_whitespace();
            let Some(fstype) = fields.next() else {
                continue;
            };
            let Some(options) = fields.next() else {
                continue;
            };
            let target = fields.next().unwrap_or("mount");
            if fstype == "swap"
                || options
                    .split(',')
                    .any(|option| option.trim().eq_ignore_ascii_case("nofail"))
                || !seen.insert(fstype.to_string())
            {
                continue;
            }
            filesystems.push(BootFilesystem {
                fstype: fstype.to_string(),
                initrd_required: false,
                reason: format!("{target} is configured without nofail"),
            });
        }

        filesystems
    }

    fn has_installed_package(&self, patterns: &[String]) -> bool {
        let args = std::iter::once("-qa")
            .chain(patterns.iter().map(String::as_str))
            .collect::<Vec<_>>();
        run_output("rpm", &args)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }

    fn has_module(&self, kernel: &str, module: &str) -> bool {
        command_success("modinfo", &["-k", kernel, module])
    }

    fn initrd_has_module(&self, kernel: &str, module: &str) -> Option<bool> {
        let output = run_output("lsinitrd", &["-k", kernel])?;
        let needles = module_needles(module);
        Some(
            output
                .lines()
                .any(|line| needles.iter().any(|needle| line.contains(needle))),
        )
    }
}

pub fn run_checks(
    probe: &dyn SystemProbe,
    requested_kernel: Option<&str>,
    extra_policies: Vec<ModulePolicy>,
) -> CheckResult {
    let mut diagnostics = Vec::new();
    let mut kernels = annotate_kernels(probe.installed_kernels(), &probe.running_kernel());
    if let Some(requested) = requested_kernel {
        kernels.retain(|kernel| kernel.uname == requested);
        if kernels.is_empty() {
            diagnostics.push(format!("requested kernel is not installed: {requested}"));
        }
    } else if let Some(hint) = probe.next_boot_kernel_hint()
        && !annotate_next_boot_kernel(&mut kernels, &hint.value)
    {
        diagnostics.push(format!(
            "next boot entry from {} does not match an installed kernel: {}",
            hint.source, hint.value
        ));
    }

    let policies = derive_kmp_policies(probe, extra_policies);
    if policies.iter().all(|policy| !policy.enabled) {
        diagnostics.push("no enabled module policies detected".to_string());
    }

    CheckResult {
        kernels: kernels
            .into_iter()
            .map(|kernel| check_kernel(kernel, &policies, probe, requested_kernel.is_some()))
            .collect(),
        diagnostics,
    }
}

pub fn exit_code(result: &CheckResult, strict: bool) -> i32 {
    match result.severity() {
        Severity::Ok => 0,
        Severity::Warning => 1,
        Severity::BootRisk => 2,
        Severity::Unknown if strict => 3,
        Severity::Unknown => 1,
    }
}

pub fn derive_kmp_policies(
    probe: &dyn SystemProbe,
    config_policies: Vec<ModulePolicy>,
) -> Vec<ModulePolicy> {
    let boot_filesystems = probe.boot_filesystems();
    let mut seen_modules = HashSet::new();
    let mut policies = Vec::new();

    for kmp_module in probe.installed_kmp_modules() {
        if !seen_modules.insert(kmp_module.module.clone()) {
            continue;
        }
        if let Some(filesystem) = boot_filesystems
            .iter()
            .find(|filesystem| filesystem.fstype == kmp_module.module)
        {
            policies.push(ModulePolicy {
                name: format!("boot-fs:{}", kmp_module.module),
                module: kmp_module.module.clone(),
                enabled: true,
                initrd: if filesystem.initrd_required {
                    InitrdPolicy::Required
                } else {
                    InitrdPolicy::Optional
                },
                severity: Severity::BootRisk,
                reason: format!(
                    "{}; filesystem is provided by KMP: {}",
                    filesystem.reason, kmp_module.package
                ),
                kernel_scope: KernelScope::All,
                source: PolicySource::BootFilesystemKmp,
            });
        } else {
            policies.push(ModulePolicy {
                name: format!("kmp:{}", kmp_module.module),
                module: kmp_module.module.clone(),
                enabled: true,
                initrd: InitrdPolicy::Optional,
                severity: Severity::Warning,
                reason: format!("KMP package is installed: {}", kmp_module.package),
                kernel_scope: KernelScope::Important,
                source: PolicySource::AutoKmp,
            });
        }
    }

    apply_config_policies(&mut policies, config_policies);
    policies
}

fn apply_config_policies(policies: &mut Vec<ModulePolicy>, config_policies: Vec<ModulePolicy>) {
    for config_policy in config_policies {
        if !config_policy.enabled && config_policy.reason == "configured as disabled" {
            policies.retain(|policy| policy.module != config_policy.module);
            continue;
        }
        if config_policy.enabled {
            policies.retain(|policy| policy.module != config_policy.module);
            policies.push(config_policy);
        }
    }
}

pub fn load_policy_dirs(paths: &[String], probe: &dyn SystemProbe) -> Vec<ModulePolicy> {
    let mut policies = Vec::new();
    for path in paths {
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        let mut files = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension() == Some(OsStr::new("conf")))
            .collect::<Vec<_>>();
        files.sort();
        for file in files {
            policies.extend(load_policy_file(&file, probe).unwrap_or_default());
        }
    }
    policies
}

fn load_policy_file(path: &Path, probe: &dyn SystemProbe) -> io::Result<Vec<ModulePolicy>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_policy_config(&content, probe))
}

pub fn parse_policy_config(content: &str, probe: &dyn SystemProbe) -> Vec<ModulePolicy> {
    let mut policies = Vec::new();
    let mut current: Option<RawPolicy> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with("[module \"") && line.ends_with("\"]") {
            if let Some(policy) = current.take() {
                policies.push(policy.finish(probe));
            }
            let name = line
                .trim_start_matches("[module \"")
                .trim_end_matches("\"]")
                .to_string();
            current = Some(RawPolicy::new(name));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if let Some(policy) = current.as_mut() {
            policy.set(key.trim(), value.trim());
        }
    }

    if let Some(policy) = current {
        policies.push(policy.finish(probe));
    }
    policies
}

pub fn human_output(result: &CheckResult) -> String {
    let mut output = String::from("KMP boot check\n");
    for diagnostic in &result.diagnostics {
        let _ = writeln!(output, "UNKNOWN: {diagnostic}");
    }
    for kernel_result in &result.kernels {
        let _ = writeln!(output, "{}", kernel_header(kernel_result));
        if kernel_result.module_results.is_empty() {
            output.push_str("  OK: no module policy applies\n");
            continue;
        }
        for module_result in &kernel_result.module_results {
            let initrd = match module_result.initrd_found {
                Some(true) => "yes",
                Some(false) => "no",
                None => "not-checked",
            };
            let _ = writeln!(
                output,
                "  {}: {}: {}; module={}; initrd={}; source={}; reason={}",
                module_result.severity.label(),
                module_result.policy.name,
                module_result.message,
                if module_result.module_found {
                    "yes"
                } else {
                    "no"
                },
                initrd,
                module_result.policy.source.label(),
                module_result.policy.reason
            );
        }
    }
    output
}

pub fn json_output(result: &CheckResult) -> String {
    let mut output = String::new();
    let _ = write!(
        output,
        "{{\"severity\":\"{}\",\"diagnostics\":[",
        result.severity().status()
    );
    for (index, diagnostic) in result.diagnostics.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write_json_string(&mut output, diagnostic);
    }
    output.push_str("],\"kernels\":[");
    for (kernel_index, kernel_result) in result.kernels.iter().enumerate() {
        if kernel_index > 0 {
            output.push(',');
        }
        output.push('{');
        output.push_str("\"uname\":");
        write_json_string(&mut output, &kernel_result.kernel.uname);
        output.push_str(",\"package\":");
        write_json_string(&mut output, &kernel_result.kernel.package);
        let _ = write!(
            output,
            ",\"running\":{},\"latest\":{},\"next_boot\":{},\"severity\":\"{}\",\"modules\":[",
            kernel_result.kernel.running,
            kernel_result.kernel.latest,
            kernel_result.kernel.next_boot,
            kernel_result.severity().status()
        );
        for (module_index, module_result) in kernel_result.module_results.iter().enumerate() {
            if module_index > 0 {
                output.push(',');
            }
            output.push('{');
            output.push_str("\"name\":");
            write_json_string(&mut output, &module_result.policy.name);
            output.push_str(",\"module\":");
            write_json_string(&mut output, &module_result.policy.module);
            let _ = write!(
                output,
                ",\"severity\":\"{}\",\"message\":",
                module_result.severity.status()
            );
            write_json_string(&mut output, &module_result.message);
            let _ = write!(
                output,
                ",\"module_found\":{},\"initrd_found\":",
                module_result.module_found
            );
            match module_result.initrd_found {
                Some(value) => output.push_str(if value { "true" } else { "false" }),
                None => output.push_str("null"),
            }
            output.push_str(",\"source\":");
            write_json_string(&mut output, module_result.policy.source.label());
            output.push_str(",\"reason\":");
            write_json_string(&mut output, &module_result.policy.reason);
            output.push('}');
        }
        output.push_str("]}");
    }
    output.push_str("]}");
    output
}

fn annotate_kernels(mut kernels: Vec<Kernel>, running: &str) -> Vec<Kernel> {
    let latest = kernels
        .iter()
        .max_by(|a, b| {
            a.install_time
                .cmp(&b.install_time)
                .then_with(|| a.uname.cmp(&b.uname))
        })
        .map(|kernel| kernel.uname.clone());
    for kernel in &mut kernels {
        kernel.running = kernel.uname == running;
        kernel.latest = latest.as_deref() == Some(kernel.uname.as_str());
    }
    kernels
}

fn annotate_next_boot_kernel(kernels: &mut [Kernel], hint: &str) -> bool {
    let Some(uname) = kernels
        .iter()
        .filter(|kernel| hint.contains(&kernel.uname))
        .max_by(|a, b| a.uname.len().cmp(&b.uname.len()))
        .map(|kernel| kernel.uname.clone())
    else {
        return false;
    };

    for kernel in kernels {
        kernel.next_boot = kernel.uname == uname;
    }
    true
}

fn check_kernel(
    kernel: Kernel,
    policies: &[ModulePolicy],
    probe: &dyn SystemProbe,
    requested_kernel: bool,
) -> KernelResult {
    let module_results = policies
        .iter()
        .filter(|policy| policy.enabled)
        .filter(|policy| {
            requested_kernel
                || policy.kernel_scope == KernelScope::All
                || kernel.next_boot
                || (policy.kernel_scope == KernelScope::Important
                    && (kernel.running || kernel.latest))
        })
        .map(|policy| check_module(&kernel, policy, probe))
        .collect();
    KernelResult {
        kernel,
        module_results,
    }
}

fn check_module(kernel: &Kernel, policy: &ModulePolicy, probe: &dyn SystemProbe) -> ModuleResult {
    let module_found = probe.has_module(&kernel.uname, &policy.module);
    let mut initrd_found = None;
    let mut severity = Severity::Ok;
    let mut message = "ok".to_string();

    if !module_found {
        severity = policy.severity;
        message = format!("missing module {}", policy.module);
    } else if policy.initrd == InitrdPolicy::Required {
        initrd_found = probe.initrd_has_module(&kernel.uname, &policy.module);
        match initrd_found {
            Some(false) => {
                severity = policy.severity;
                message = format!("module {} is not present in initrd", policy.module);
            }
            None => {
                severity = Severity::Unknown;
                message = format!("could not inspect initrd for {}", policy.module);
            }
            Some(true) => {}
        }
    } else if policy.initrd == InitrdPolicy::Auto {
        initrd_found = probe.initrd_has_module(&kernel.uname, &policy.module);
    }

    ModuleResult {
        policy: policy.clone(),
        module_found,
        initrd_found,
        severity,
        message,
    }
}

fn kernel_header(result: &KernelResult) -> String {
    let mut labels = Vec::new();
    if result.kernel.running {
        labels.push("running");
    }
    if result.kernel.latest {
        labels.push("latest");
    }
    if result.kernel.next_boot {
        labels.push("next-boot");
    }
    let suffix = if labels.is_empty() {
        String::new()
    } else {
        format!(" ({})", labels.join(", "))
    };
    format!(
        "{}: kernel {}{}",
        result.severity().label(),
        result.kernel.uname,
        suffix
    )
}

#[derive(Debug)]
struct RawPolicy {
    name: String,
    module: Option<String>,
    detect: String,
    initrd: InitrdPolicy,
    severity: Severity,
    kernel_scope: KernelScope,
    enabled: Option<bool>,
}

impl RawPolicy {
    fn new(name: String) -> Self {
        Self {
            name,
            module: None,
            detect: "always".to_string(),
            initrd: InitrdPolicy::Optional,
            severity: Severity::Warning,
            kernel_scope: KernelScope::All,
            enabled: None,
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        match key {
            "module" => self.module = Some(value.to_string()),
            "detect" => self.detect = value.to_string(),
            "initrd" => self.initrd = parse_initrd_policy(value),
            "severity" => self.severity = parse_severity(value),
            "scope" => self.kernel_scope = parse_kernel_scope(value),
            "enabled" => self.enabled = Some(parse_bool(value)),
            _ => {}
        }
    }

    fn finish(self, probe: &dyn SystemProbe) -> ModulePolicy {
        let (detected, detect_reason) = detect_policy(&self.detect, probe);
        let enabled = detected && self.enabled.unwrap_or(true);
        let reason = if self.enabled == Some(false) {
            "configured as disabled".to_string()
        } else {
            detect_reason
        };
        ModulePolicy {
            module: self.module.unwrap_or_else(|| self.name.clone()),
            name: self.name,
            enabled,
            initrd: self.initrd,
            severity: self.severity,
            reason,
            kernel_scope: self.kernel_scope,
            source: PolicySource::Config,
        }
    }
}

fn detect_policy(value: &str, probe: &dyn SystemProbe) -> (bool, String) {
    let value = value.trim();
    if value == "always" {
        return (true, "configured as always".to_string());
    }
    if value == "never" {
        return (false, "configured as never".to_string());
    }
    if let Some(fstype) = value.strip_prefix("rootfs:") {
        return (
            probe.root_fstype() == fstype.trim(),
            format!("/ is mounted as {}", fstype.trim()),
        );
    }
    if let Some(patterns) = value.strip_prefix("package:") {
        let patterns = patterns
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        return (
            probe.has_installed_package(&patterns),
            format!("package pattern matched: {}", patterns.join(", ")),
        );
    }
    (false, format!("unsupported detect value: {value}"))
}

fn parse_initrd_policy(value: &str) -> InitrdPolicy {
    match value.trim().to_ascii_lowercase().as_str() {
        "required" => InitrdPolicy::Required,
        "auto" => InitrdPolicy::Auto,
        _ => InitrdPolicy::Optional,
    }
}

fn parse_severity(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "boot-risk" | "risk" => Severity::BootRisk,
        "unknown" => Severity::Unknown,
        _ => Severity::Warning,
    }
}

fn parse_kernel_scope(value: &str) -> KernelScope {
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "next-boot" | "nextboot" => KernelScope::NextBoot,
        "important" => KernelScope::Important,
        _ => KernelScope::All,
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}

fn parse_kmod_provide(value: &str) -> Option<String> {
    let module = value.strip_prefix("kmod(")?.split_once(".ko)")?.0.trim();
    if module.is_empty() {
        return None;
    }
    Some(module.to_string())
}

fn module_needles(module: &str) -> Vec<String> {
    let base = module.replace('-', "_");
    vec![
        format!("/{base}.ko"),
        format!("/{base}.ko."),
        format!(" {base}.ko"),
        format!(" {base}.ko."),
    ]
}

fn extract_bootctl_default_entry(output: &str) -> Option<String> {
    let normalized = output.replace(char::is_whitespace, "");
    for object in json_objects(&normalized) {
        if object.contains("\"isDefault\":true") || object.contains("\"default\":true") {
            return Some(object.to_string());
        }
    }
    None
}

fn extract_bootctl_status_default_entry(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Default Entry:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn json_objects(value: &str) -> Vec<&str> {
    let mut objects = Vec::new();
    let mut start = None;
    let mut depth = 0usize;
    let mut escaped = false;
    let mut in_string = false;

    for (index, byte) in value.bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth += 1;
            }
            b'}' if depth > 0 => {
                depth -= 1;
                if depth == 0
                    && let Some(start) = start.take()
                {
                    objects.push(&value[start..=index]);
                }
            }
            _ => {}
        }
    }

    objects
}

fn run_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_output_any_status(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if output.stdout.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn command_success(command: &str, args: &[&str]) -> bool {
    Command::new(command)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn write_json_string(output: &mut String, value: &str) {
    output.push('"');
    for c in value.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(output, "\\u{:04x}", c as u32);
            }
            c => output.push(c),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct FakeProbe {
        kernels: Vec<Kernel>,
        kmp_modules: Vec<KmpModule>,
        running: String,
        next_boot_hint: Option<NextBootHint>,
        root_fstype: String,
        boot_filesystems: Vec<BootFilesystem>,
        has_packages: bool,
        modules: HashSet<(String, String)>,
        initrd: HashMap<(String, String), Option<bool>>,
    }

    impl FakeProbe {
        fn new() -> Self {
            Self {
                running: "1-default".to_string(),
                root_fstype: "btrfs".to_string(),
                ..Self::default()
            }
        }
    }

    impl SystemProbe for FakeProbe {
        fn installed_kernels(&self) -> Vec<Kernel> {
            self.kernels.clone()
        }

        fn installed_kmp_modules(&self) -> Vec<KmpModule> {
            self.kmp_modules.clone()
        }

        fn running_kernel(&self) -> String {
            self.running.clone()
        }

        fn next_boot_kernel_hint(&self) -> Option<NextBootHint> {
            self.next_boot_hint.clone()
        }

        fn root_fstype(&self) -> String {
            self.root_fstype.clone()
        }

        fn boot_filesystems(&self) -> Vec<BootFilesystem> {
            if self.boot_filesystems.is_empty() {
                return vec![BootFilesystem {
                    fstype: self.root_fstype.clone(),
                    initrd_required: true,
                    reason: "/ is a boot-required mount".to_string(),
                }];
            }
            self.boot_filesystems.clone()
        }

        fn has_installed_package(&self, _patterns: &[String]) -> bool {
            self.has_packages
        }

        fn has_module(&self, kernel: &str, module: &str) -> bool {
            self.modules
                .contains(&(kernel.to_string(), module.to_string()))
        }

        fn initrd_has_module(&self, kernel: &str, module: &str) -> Option<bool> {
            self.initrd
                .get(&(kernel.to_string(), module.to_string()))
                .copied()
                .flatten()
        }
    }

    #[test]
    fn runtime_kmp_missing_on_latest_is_warning() {
        let mut probe = FakeProbe::new();
        probe.kernels = vec![
            Kernel {
                uname: "1-default".to_string(),
                package: String::new(),
                install_time: 1,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "2-default".to_string(),
                package: String::new(),
                install_time: 2,
                running: false,
                latest: false,
                next_boot: false,
            },
        ];
        probe.kmp_modules = vec![KmpModule {
            package: "vendor_gpu-kmp-default-1-1.x86_64".to_string(),
            module: "vendor_gpu".to_string(),
        }];
        probe
            .modules
            .insert(("1-default".to_string(), "vendor_gpu".to_string()));

        let result = run_checks(&probe, None, Vec::new());

        assert_eq!(result.severity(), Severity::Warning);
        assert_eq!(exit_code(&result, false), 1);
        assert_eq!(
            result
                .kernels
                .iter()
                .find(|kernel| kernel.kernel.latest)
                .unwrap()
                .kernel
                .uname,
            "2-default"
        );
    }

    #[test]
    fn boot_filesystem_kmp_missing_initrd_is_boot_risk() {
        let mut probe = FakeProbe::new();
        probe.root_fstype = "myfs".to_string();
        probe.kernels = vec![Kernel {
            uname: "2-default".to_string(),
            package: String::new(),
            install_time: 2,
            running: false,
            latest: false,
            next_boot: false,
        }];
        probe.kmp_modules = vec![KmpModule {
            package: "myfs-kmp-default-1-1.x86_64".to_string(),
            module: "myfs".to_string(),
        }];
        probe
            .modules
            .insert(("2-default".to_string(), "myfs".to_string()));
        probe
            .initrd
            .insert(("2-default".to_string(), "myfs".to_string()), Some(false));

        let result = run_checks(&probe, None, Vec::new());

        assert_eq!(result.severity(), Severity::BootRisk);
        assert_eq!(exit_code(&result, true), 2);
    }

    #[test]
    fn non_nofail_filesystem_kmp_is_boot_risk_without_initrd_requirement() {
        let mut probe = FakeProbe::new();
        probe.boot_filesystems = vec![BootFilesystem {
            fstype: "datafs".to_string(),
            initrd_required: false,
            reason: "/srv is configured without nofail".to_string(),
        }];
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: true,
            latest: false,
            next_boot: false,
        }];
        probe.kmp_modules = vec![KmpModule {
            package: "datafs-kmp-default-1-1.x86_64".to_string(),
            module: "datafs".to_string(),
        }];
        probe
            .modules
            .insert(("1-default".to_string(), "datafs".to_string()));

        let result = run_checks(&probe, None, Vec::new());

        assert_eq!(result.severity(), Severity::Ok);
        assert_eq!(
            result.kernels[0].module_results[0].policy.severity,
            Severity::BootRisk
        );
        assert_eq!(
            result.kernels[0].module_results[0].policy.initrd,
            InitrdPolicy::Optional
        );
        assert_eq!(
            result.kernels[0].module_results[0].policy.source,
            PolicySource::BootFilesystemKmp
        );
    }

    #[test]
    fn requested_unknown_kernel_is_unknown() {
        let mut probe = FakeProbe::new();
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: false,
            latest: false,
            next_boot: false,
        }];

        let result = run_checks(&probe, Some("2-default"), Vec::new());

        assert_eq!(result.severity(), Severity::Unknown);
        assert_eq!(exit_code(&result, true), 3);
    }

    #[test]
    fn config_package_detection() {
        let mut probe = FakeProbe::new();
        probe.has_packages = true;
        let policies = parse_policy_config(
            r#"
            [module "v4l2loopback"]
            detect = package:v4l2loopback-kmp-*
            module = v4l2loopback
            initrd = optional
            severity = warning
            scope = important
            "#,
            &probe,
        );

        assert_eq!(policies.len(), 1);
        assert!(policies[0].enabled);
        assert_eq!(policies[0].module, "v4l2loopback");
        assert_eq!(policies[0].severity, Severity::Warning);
        assert_eq!(policies[0].kernel_scope, KernelScope::Important);
    }

    #[test]
    fn generic_kmp_modules_are_warning_policies() {
        let mut probe = FakeProbe::new();
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: false,
            latest: false,
            next_boot: false,
        }];
        probe.kmp_modules = vec![KmpModule {
            package: "v4l2loopback-kmp-default-1-1.x86_64".to_string(),
            module: "v4l2loopback".to_string(),
        }];

        let result = run_checks(&probe, None, Vec::new());

        assert_eq!(result.severity(), Severity::Warning);
        assert_eq!(
            result.kernels[0].module_results[0].policy.name,
            "kmp:v4l2loopback"
        );
        assert_eq!(
            result.kernels[0].module_results[0].policy.source,
            PolicySource::AutoKmp
        );
    }

    #[test]
    fn generic_kmp_modules_skip_non_important_kernels() {
        let mut probe = FakeProbe::new();
        probe.running = "2-default".to_string();
        probe.kernels = vec![
            Kernel {
                uname: "1-default".to_string(),
                package: String::new(),
                install_time: 1,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "2-default".to_string(),
                package: String::new(),
                install_time: 2,
                running: false,
                latest: false,
                next_boot: false,
            },
        ];
        probe.kmp_modules = vec![KmpModule {
            package: "v4l2loopback-kmp-default-1-1.x86_64".to_string(),
            module: "v4l2loopback".to_string(),
        }];
        probe
            .modules
            .insert(("2-default".to_string(), "v4l2loopback".to_string()));

        let result = run_checks(&probe, None, Vec::new());

        assert!(result.kernels[0].module_results.is_empty());
        assert_eq!(result.severity(), Severity::Ok);
    }

    #[test]
    fn next_boot_hint_marks_matching_installed_kernel() {
        let mut probe = FakeProbe::new();
        probe.running = "1-default".to_string();
        probe.next_boot_hint = Some(NextBootHint {
            source: "test".to_string(),
            value: "openSUSE-2-default.conf".to_string(),
        });
        probe.kernels = vec![
            Kernel {
                uname: "1-default".to_string(),
                package: String::new(),
                install_time: 1,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "2-default".to_string(),
                package: String::new(),
                install_time: 2,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "3-default".to_string(),
                package: String::new(),
                install_time: 3,
                running: false,
                latest: false,
                next_boot: false,
            },
        ];
        probe.kmp_modules = vec![KmpModule {
            package: "vendor_gpu-kmp-default-1-1.x86_64".to_string(),
            module: "vendor_gpu".to_string(),
        }];
        probe
            .modules
            .insert(("1-default".to_string(), "vendor_gpu".to_string()));
        probe
            .modules
            .insert(("3-default".to_string(), "vendor_gpu".to_string()));

        let result = run_checks(&probe, None, Vec::new());

        assert!(result.diagnostics.is_empty());
        assert_eq!(result.severity(), Severity::Warning);
        assert!(
            result
                .kernels
                .iter()
                .find(|kernel| kernel.kernel.uname == "2-default")
                .unwrap()
                .kernel
                .next_boot
        );
    }

    #[test]
    fn unmatched_next_boot_hint_is_diagnostic() {
        let mut probe = FakeProbe::new();
        probe.next_boot_hint = Some(NextBootHint {
            source: "test".to_string(),
            value: "openSUSE-9-default.conf".to_string(),
        });
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: true,
            latest: false,
            next_boot: false,
        }];

        let result = run_checks(&probe, None, Vec::new());

        assert_eq!(result.severity(), Severity::Unknown);
        assert!(result.diagnostics[0].contains("does not match an installed kernel"));
    }

    #[test]
    fn next_boot_scope_checks_only_next_boot_kernel() {
        let mut probe = FakeProbe::new();
        probe.running = "1-default".to_string();
        probe.next_boot_hint = Some(NextBootHint {
            source: "test".to_string(),
            value: "2-default".to_string(),
        });
        probe.kernels = vec![
            Kernel {
                uname: "1-default".to_string(),
                package: String::new(),
                install_time: 1,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "2-default".to_string(),
                package: String::new(),
                install_time: 2,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "3-default".to_string(),
                package: String::new(),
                install_time: 3,
                running: false,
                latest: false,
                next_boot: false,
            },
        ];
        probe.has_packages = true;
        let policies = parse_policy_config(
            r#"
            [module "vendor_gpu"]
            detect = package:vendor_gpu-kmp-*
            module = vendor_gpu
            scope = next-boot
            severity = warning
            "#,
            &probe,
        );

        let result = run_checks(&probe, None, policies);

        assert!(result.kernels[0].module_results.is_empty());
        assert_eq!(result.kernels[1].module_results.len(), 1);
        assert!(result.kernels[2].module_results.is_empty());
        assert_eq!(result.severity(), Severity::Warning);
    }

    #[test]
    fn requested_kernel_does_not_depend_on_next_boot_hint() {
        let mut probe = FakeProbe::new();
        probe.next_boot_hint = Some(NextBootHint {
            source: "test".to_string(),
            value: "1-default".to_string(),
        });
        probe.kernels = vec![
            Kernel {
                uname: "1-default".to_string(),
                package: String::new(),
                install_time: 1,
                running: false,
                latest: false,
                next_boot: false,
            },
            Kernel {
                uname: "2-default".to_string(),
                package: String::new(),
                install_time: 2,
                running: false,
                latest: false,
                next_boot: false,
            },
        ];
        probe.has_packages = true;
        let policies = parse_policy_config(
            r#"
            [module "vendor_gpu"]
            detect = package:vendor_gpu-kmp-*
            module = vendor_gpu
            scope = next-boot
            severity = warning
            "#,
            &probe,
        );

        let result = run_checks(&probe, Some("2-default"), policies);

        assert_eq!(result.kernels.len(), 1);
        assert_eq!(result.kernels[0].kernel.uname, "2-default");
        assert_eq!(result.kernels[0].module_results.len(), 1);
        assert!(!result.kernels[0].kernel.next_boot);
    }

    #[test]
    fn config_can_override_auto_kmp_policy() {
        let mut probe = FakeProbe::new();
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: true,
            latest: false,
            next_boot: false,
        }];
        probe.kmp_modules = vec![KmpModule {
            package: "vendor_net-kmp-default-1-1.x86_64".to_string(),
            module: "vendor_net".to_string(),
        }];
        let policies = parse_policy_config(
            r#"
            [module "vendor_net"]
            initrd = required
            severity = boot-risk
            scope = all
            "#,
            &probe,
        );

        let result = run_checks(&probe, None, policies);

        assert_eq!(
            result.kernels[0].module_results[0].policy.source,
            PolicySource::Config
        );
        assert_eq!(result.severity(), Severity::BootRisk);
    }

    #[test]
    fn config_accepts_next_boot_scope() {
        let probe = FakeProbe::new();
        let policies = parse_policy_config(
            r#"
            [module "vendor_gpu"]
            scope = next-boot
            "#,
            &probe,
        );

        assert_eq!(policies[0].kernel_scope, KernelScope::NextBoot);
    }

    #[test]
    fn config_can_disable_auto_kmp_policy() {
        let mut probe = FakeProbe::new();
        probe.kernels = vec![Kernel {
            uname: "1-default".to_string(),
            package: String::new(),
            install_time: 1,
            running: true,
            latest: false,
            next_boot: false,
        }];
        probe.kmp_modules = vec![KmpModule {
            package: "vendor_cam-kmp-default-1-1.x86_64".to_string(),
            module: "vendor_cam".to_string(),
        }];
        let policies = parse_policy_config(
            r#"
            [module "vendor_cam"]
            enabled = false
            "#,
            &probe,
        );

        let result = run_checks(&probe, None, policies);

        assert_eq!(result.severity(), Severity::Unknown);
        assert!(result.kernels[0].module_results.is_empty());
    }

    #[test]
    fn parse_kmod_provide_strips_suffix() {
        assert_eq!(
            parse_kmod_provide("kmod(vendor_drm.ko)"),
            Some("vendor_drm".to_string())
        );
    }

    #[test]
    fn bootctl_json_default_entry_is_extracted() {
        let output = r#"
        [
          {"id":"old.conf","title":"old","isDefault":false},
          {"id":"opensuse-2-default.conf","title":"openSUSE 2","isDefault":true}
        ]
        "#;

        assert_eq!(
            extract_bootctl_default_entry(output),
            Some(
                "{\"id\":\"opensuse-2-default.conf\",\"title\":\"openSUSE2\",\"isDefault\":true}"
                    .to_string()
            )
        );
    }

    #[test]
    fn bootctl_status_default_entry_is_extracted() {
        let output = r#"
        Current Boot Loader:
               Product: GRUB2 2.14
         Current Entry: system-opensuse-tumbleweed-7.0.1-default-1.conf
         Default Entry: system-opensuse-tumbleweed-7.0.2-default-1.conf
        "#;

        assert_eq!(
            extract_bootctl_status_default_entry(output),
            Some("system-opensuse-tumbleweed-7.0.2-default-1.conf".to_string())
        );
    }

    #[test]
    fn json_escapes_strings() {
        let result = CheckResult {
            kernels: Vec::new(),
            diagnostics: vec!["quote \" newline\n".to_string()],
        };

        assert!(json_output(&result).contains("quote \\\" newline\\n"));
    }
}
