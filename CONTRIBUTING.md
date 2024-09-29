# Contributing to `jwt-compact`

This project welcomes contribution from everyone, which can take form of suggestions / feature requests, bug reports, or pull requests.
This document provides guidance how best to contribute.

## Bug reports and feature requests

For bugs or when asking for help, please use the bug issue template and include enough details so that your observations
can be reproduced.

For feature requests, please use the feature request issue template and describe the intended use case(s) and motivation
to go for them. If possible, include your ideas how to implement the feature, potential alternatives and disadvantages.

## Pull requests

Please use the pull request template when submitting a PR. List the major goal(s) achieved by the PR
and describe the motivation behind it. If applicable, like to the related issue(s).

Optimally, you should check locally that the CI checks pass before submitting the PR. Checks included in the CI
include:

- Formatting using `cargo fmt --all -- --config imports_granularity=Crate --config group_imports=StdExternalCrate`
- Linting using `cargo clippy`
- Linting the dependency graph using [`cargo deny`](https://crates.io/crates/cargo-deny)
- Running the test suite using `cargo test`

A complete list of checks can be viewed in [the CI workflow file](.github/workflows/ci.yml). The checks are run
on the latest stable Rust version.

### MSRV checks

A part of the CI assertions is the minimum supported Rust version (MSRV). If this check fails, consult the error messages. Depending on
the error (e.g., whether it is caused by a newer language feature used in the PR code, or in a dependency),
you might want to rework the PR, get rid of the offending dependency, or bump the MSRV; don't hesitate to consult the maintainers.

### No-std support checks

Another part of the CI assertions is no-std compatibility of the project. To check it locally, install a no-std Rust target
(CI uses `thumbv7m-none-eabi`) and build the project libraries for it. Keep in mind that no-std compatibility may be broken
by dependencies.

## Code of Conduct

Be polite and respectful.
