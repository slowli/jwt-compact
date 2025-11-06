use version_sync::{assert_html_root_url_updated, assert_markdown_deps_updated};

#[test]
fn readme_is_in_sync() {
    assert_markdown_deps_updated!("README.md");
}

#[test]
fn html_root_url_is_in_sync() {
    assert_html_root_url_updated!("src/lib.rs");
}
