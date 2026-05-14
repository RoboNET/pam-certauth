//! Integration test for the `execute` subcommand argument parsing.

use clap::Parser;
use pam_certauth_cli::execute::cli::ExecuteArgs;

#[derive(clap::Parser)]
struct TestCli {
    #[command(subcommand)]
    cmd: TestCmd,
}

#[derive(clap::Subcommand)]
enum TestCmd {
    Execute(ExecuteArgs),
}

#[test]
fn parses_execute_with_scope_and_work_order_and_cmd() {
    let cli = TestCli::parse_from([
        "test",
        "execute",
        "--scope",
        "bios.flash",
        "--work-order",
        "/tmp/wo.cms",
        "--",
        "flashrom",
        "-w",
        "fw.bin",
    ]);
    let TestCmd::Execute(args) = cli.cmd;
    assert_eq!(args.scope.as_deref(), Some("bios.flash"));
    assert_eq!(
        args.work_order.as_deref(),
        Some(std::path::Path::new("/tmp/wo.cms"))
    );
    assert_eq!(args.cmd, vec!["flashrom", "-w", "fw.bin"]);
}
