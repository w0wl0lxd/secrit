# secrit

secrit is a small Rust command-line tool that stores secrets in a sops + age file that
sops-nix can read. You type `secrit store NAME`, and secrit reads the value from a no-echo
prompt or from stdin. The value never goes on the command line, never reaches the terminal
scrollback, and the write is crash-safe and lock-protected. The design is in
[`docs/PLAN.md`](docs/PLAN.md).
