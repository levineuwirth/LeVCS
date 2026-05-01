//! `levcs` command-line interface.

use anyhow::Result;

mod cli;
mod ctx;
mod fed_cmds;
mod identity_cmds;
mod repo_cmds;
mod tree_helpers;

use clap::Parser;

fn main() {
    if let Err(e) = run() {
        eprintln!("levcs: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = cli::Cli::parse();
    match args.command {
        cli::Cmd::Init(a) => repo_cmds::init(a),
        cli::Cmd::Track(a) => repo_cmds::track(a),
        cli::Cmd::Forget(a) => repo_cmds::forget(a),
        cli::Cmd::Commit(a) => repo_cmds::commit(a),
        cli::Cmd::Construct(a) => repo_cmds::construct(a),
        cli::Cmd::Diff(a) => repo_cmds::diff(a),
        cli::Cmd::Branch(a) => repo_cmds::branch(a),
        cli::Cmd::Merge(a) => repo_cmds::merge(a),
        cli::Cmd::Release(a) => repo_cmds::release(a),
        cli::Cmd::Cache(a) => repo_cmds::cache(a),
        cli::Cmd::Status => repo_cmds::status(),
        cli::Cmd::Log(a) => repo_cmds::log(a),
        cli::Cmd::Root => repo_cmds::root(),
        cli::Cmd::Verify => repo_cmds::verify(),
        cli::Cmd::Gc(a) => repo_cmds::gc(a),
        cli::Cmd::Key(a) => identity_cmds::key(a),
        cli::Cmd::Authority(a) => identity_cmds::authority(a),
        cli::Cmd::Instance(a) => fed_cmds::instance(a),
        cli::Cmd::Push(a) => fed_cmds::push(a),
        cli::Cmd::Pull(a) => fed_cmds::pull(a),
        cli::Cmd::Fork(a) => fed_cmds::fork(a),
        cli::Cmd::Inspect(a) => fed_cmds::inspect(a),
        cli::Cmd::Deploy(a) => fed_cmds::deploy(a),
        cli::Cmd::Dial(a) => fed_cmds::dial(a),
        cli::Cmd::Migrate(a) => fed_cmds::migrate(a),
    }
}
