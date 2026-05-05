use kmp_boot_check::{InitrdPolicy, RealSystemProbe, SystemProbe, parse_policy_config};

#[test]
fn initrd_policy_parser_accepts_required() {
    let probe = RealSystemProbe;
    let policies = parse_policy_config(
        r#"
        [module "zfs"]
        detect = never
        initrd = required
        severity = boot-risk
        "#,
        &probe,
    );

    assert_eq!(policies[0].initrd, InitrdPolicy::Required);
}

#[test]
fn real_probe_trait_is_usable() {
    let probe = RealSystemProbe;
    let _ = probe.running_kernel();
}
