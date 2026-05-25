//! Release notes fetching and caching for version change emails.
//!
//! Implements a three-tier fallback:
//! - **Tier C** (no config): returns `(None, None)` — no link or excerpt.
//! - **Tier A** (URL template only): returns `(Some(url), None)` — link shown, no excerpt.
//! - **Tier B** (API configured and reachable): returns `(Some(url), Some(html_excerpt))`.
//!
//! The excerpt is rendered from Markdown to a small HTML fragment using `pulldown-cmark`,
//! then truncated at a paragraph boundary. It is safe to embed directly in the email template
//! via Askama's `|safe` filter.

use crate::config::AppConfig;
use dashmap::DashMap;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd, html as md_html};
use std::time::{Duration, Instant};

pub type ReleaseCache = DashMap<(String, String), CachedRelease>;

#[derive(Debug, Clone)]
pub struct CachedRelease {
    pub release_url: Option<String>,
    pub excerpt: Option<String>,
    pub fetched_at: Instant,
}

const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Returns `(release_url, excerpt)` for the given software/version pair.
#[tracing::instrument(skip(config, cache))]
pub async fn get_release_info(
    config: &AppConfig,
    cache: &ReleaseCache,
    software_name: &str,
    version_string: &str,
) -> (Option<String>, Option<String>) {
    let key = software_name.to_lowercase();
    let Some(source) = config.release_sources.get(&key) else {
        tracing::debug!(
            software = software_name,
            "No release_sources entry — skipping release notes"
        );
        return (None, None);
    };
    tracing::debug!(software = software_name, api_type = ?source.api_type, "Found release_sources entry");

    let release_url = source
        .release_url_template
        .as_deref()
        .map(|t| t.replace("{version}", version_string));

    let cache_key = (key, version_string.to_string());

    if let Some(cached) = cache.get(&cache_key)
        && cached.fetched_at.elapsed() < CACHE_TTL
    {
        return (cached.release_url.clone(), cached.excerpt.clone());
    }

    let excerpt = if let (Some(api_type), Some(api_repo)) = (&source.api_type, &source.api_repo) {
        match api_type.as_str() {
            "github" => fetch_github_release(api_repo, version_string).await,
            "forgejo" | "gitea" => {
                let base = source
                    .api_base_url
                    .as_deref()
                    .unwrap_or("https://codeberg.org");
                fetch_forgejo_release(base, api_repo, version_string).await
            }
            other => {
                tracing::warn!(
                    api_type = other,
                    "Unknown release API type — skipping fetch"
                );
                None
            }
        }
    } else {
        None
    };

    let result = (release_url.clone(), excerpt.clone());
    cache.insert(
        cache_key,
        CachedRelease {
            release_url,
            excerpt,
            fetched_at: Instant::now(),
        },
    );
    result
}

/// Fetch a release excerpt directly without going through the config/cache.
/// Used by the debug endpoint so operators can test any repo without adding config first.
pub async fn fetch_release_excerpt_direct(
    api_type: &str,
    api_repo: &str,
    api_base_url: Option<&str>,
    version: &str,
) -> Option<String> {
    match api_type {
        "github" => fetch_github_release(api_repo, version).await,
        "forgejo" | "gitea" => {
            let base = api_base_url.unwrap_or("https://codeberg.org");
            fetch_forgejo_release(base, api_repo, version).await
        }
        other => {
            tracing::warn!(api_type = other, "Unknown release API type in direct fetch");
            None
        }
    }
}

async fn fetch_github_release(repo: &str, version: &str) -> Option<String> {
    let client = build_client()?;
    for tag in [format!("v{version}"), version.to_string()] {
        let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
        if let Some(body) = fetch_release_body(&client, &url).await {
            return Some(render_markdown_excerpt(&body));
        }
    }
    None
}

async fn fetch_forgejo_release(base_url: &str, repo: &str, version: &str) -> Option<String> {
    let client = build_client()?;
    let base = base_url.trim_end_matches('/');
    for tag in [format!("v{version}"), version.to_string()] {
        let url = format!("{base}/api/v1/repos/{repo}/releases/tags/{tag}");
        if let Some(body) = fetch_release_body(&client, &url).await {
            return Some(render_markdown_excerpt(&body));
        }
    }
    None
}

fn build_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!(
            "federation-tester/",
            env!("CARGO_PKG_VERSION"),
            " (release-notes-fetcher)"
        ))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| tracing::warn!(error = %e, "Failed to build reqwest client"))
        .ok()
}

async fn fetch_release_body(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| tracing::warn!(error = %e, url, "Release API request failed"))
        .ok()?;

    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), url, "Release API returned non-2xx — check rate limits or repo path");
        return None;
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| tracing::debug!(error = %e, "Failed to parse release API JSON"))
        .ok()?;

    let body = json.get("body")?.as_str()?;
    if body.is_empty() {
        None
    } else {
        Some(body.to_string())
    }
}

/// Maximum number of top-level block elements included in an excerpt.
const MAX_BLOCKS: usize = 6;

/// Render a Markdown release-notes body to a small inline-styled HTML fragment.
///
/// Uses pulldown-cmark's built-in HTML renderer for correctness, filters to
/// `MAX_BLOCKS` top-level blocks, then applies email-safe inline styles.
fn render_markdown_excerpt(body: &str) -> String {
    let opts = Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TABLES
        | Options::ENABLE_GFM
        | Options::ENABLE_TASKLISTS;

    let parser = Parser::new_ext(body, opts);
    let (events, truncated) = collect_first_blocks(parser, MAX_BLOCKS);

    let mut raw_html = String::new();
    md_html::push_html(&mut raw_html, events.into_iter());

    let mut out = apply_email_styles(&raw_html);
    if truncated {
        out.push_str("<p style=\"margin:4px 0 0;font-size:12px;color:#4D4844;\">…</p>");
    }
    out
}

/// Collect events for the first `max_blocks` top-level block elements, replacing
/// images with their alt text and dropping raw HTML events.
fn collect_first_blocks<'a>(parser: Parser<'a>, max_blocks: usize) -> (Vec<Event<'a>>, bool) {
    let mut out = Vec::new();
    let mut block_depth: i32 = 0;
    let mut block_count = 0usize;
    let mut in_image = false;
    let mut image_alt = String::new();

    for event in parser {
        // Inside an image tag: accumulate alt text, emit as Text on End.
        if in_image {
            match event {
                Event::Text(t) => image_alt.push_str(&t),
                Event::End(TagEnd::Image) => {
                    in_image = false;
                    if !image_alt.is_empty() {
                        out.push(Event::Text(std::mem::take(&mut image_alt).into()));
                    }
                }
                _ => {}
            }
            continue;
        }

        match event {
            // Drop raw HTML — don't let it pass through to push_html.
            Event::Html(_) | Event::InlineHtml(_) => continue,

            // Images → alt text (handled above on next iterations).
            Event::Start(Tag::Image { .. }) => {
                in_image = true;
                image_alt.clear();
                continue;
            }

            // Block-level openers: count and stop when we hit the limit.
            Event::Start(ref tag) if is_top_level_block(tag) => {
                if block_depth == 0 {
                    if block_count >= max_blocks {
                        return (out, true);
                    }
                    block_count += 1;
                }
                block_depth += 1;
                out.push(event);
            }
            Event::End(ref tag) if is_top_level_block_end(tag) => {
                block_depth -= 1;
                out.push(event);
            }

            other => out.push(other),
        }
    }

    (out, false)
}

fn is_top_level_block(tag: &Tag) -> bool {
    matches!(
        tag,
        Tag::Paragraph
            | Tag::Heading { .. }
            | Tag::List(_)
            | Tag::CodeBlock(_)
            | Tag::BlockQuote(_)
            | Tag::Table(_)
    )
}

fn is_top_level_block_end(tag: &TagEnd) -> bool {
    matches!(
        tag,
        TagEnd::Paragraph
            | TagEnd::Heading(_)
            | TagEnd::List(_)
            | TagEnd::CodeBlock
            | TagEnd::BlockQuote(_)
            | TagEnd::Table
    )
}

/// Post-process pulldown-cmark's HTML output to add inline styles for email clients.
///
/// pulldown-cmark's renderer emits clean, attribute-free tags like `<p>`, `<ul>`,
/// `<li>`, `<h2>` etc., so simple string replacement is reliable here.
fn apply_email_styles(html: &str) -> String {
    // Headings → styled bold paragraphs
    let html = html
        .replace(
            "<h1>",
            "<p style=\"margin:8px 0 4px;font-size:15px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h1>", "</p>")
        .replace(
            "<h2>",
            "<p style=\"margin:8px 0 4px;font-size:14px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h2>", "</p>")
        .replace(
            "<h3>",
            "<p style=\"margin:8px 0 4px;font-size:13px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h3>", "</p>")
        .replace(
            "<h4>",
            "<p style=\"margin:8px 0 4px;font-size:13px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h4>", "</p>")
        .replace(
            "<h5>",
            "<p style=\"margin:8px 0 4px;font-size:13px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h5>", "</p>")
        .replace(
            "<h6>",
            "<p style=\"margin:8px 0 4px;font-size:13px;font-weight:700;color:#1B1714;\">",
        )
        .replace("</h6>", "</p>");

    html.replace(
        "<p>",
        "<p style=\"margin:0 0 8px;font-size:13px;color:#2F2A25;line-height:1.6;\">",
    )
    .replace(
        "<ul>",
        "<ul style=\"margin:0 0 8px;padding-left:18px;\">",
    )
    .replace(
        "<ol>",
        "<ol style=\"margin:0 0 8px;padding-left:18px;\">",
    )
    .replace(
        "<li>",
        "<li style=\"margin-bottom:2px;font-size:13px;color:#2F2A25;line-height:1.5;\">",
    )
    .replace(
        "<code>",
        "<code style=\"font-family:ui-monospace,monospace;font-size:12px;background:#EFE9DB;padding:1px 3px;border-radius:3px;\">",
    )
    .replace(
        "<a ",
        "<a style=\"color:#133A60;\" ",
    )
    .replace("<blockquote>", "<blockquote style=\"margin:0 0 8px;padding-left:12px;border-left:3px solid #C9C2AE;color:#4D4844;\">")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_heading_as_bold_p() {
        let html = render_markdown_excerpt("## Security Fixes\n\nSome text.");
        assert!(html.contains("font-weight:700"));
        assert!(html.contains("Security Fixes"));
    }

    #[test]
    fn renders_bold() {
        let html = render_markdown_excerpt("**Important:** something changed");
        assert!(html.contains("<strong>"));
        assert!(html.contains("Important:"));
    }

    #[test]
    fn renders_list_items() {
        let html = render_markdown_excerpt("- Fix a bug\n- Another fix");
        assert!(html.contains("<ul"));
        assert!(html.contains("<li"));
        assert!(html.contains("Fix a bug"));
    }

    #[test]
    fn stops_after_max_blocks() {
        let body = (0..20)
            .map(|i| format!("## Heading {i}\n\nSome text here.\n"))
            .collect::<Vec<_>>()
            .join("\n");
        let html = render_markdown_excerpt(&body);
        // Should have the ellipsis paragraph
        assert!(html.contains("…"), "expected ellipsis but got: {html}");
    }

    #[test]
    fn short_body_no_ellipsis() {
        let html = render_markdown_excerpt("Short release note.\n\nJust one fix.");
        assert!(!html.contains("…"), "short body should not be truncated");
        assert!(html.contains("Short release note."));
    }

    #[test]
    fn drops_inline_html() {
        // pulldown-cmark emits inline HTML as InlineHtml events which we drop,
        // so raw HTML tags are never echoed into the output.
        let html = render_markdown_excerpt("Fix for <script>alert(1)</script> bug");
        assert!(
            !html.contains("<script>"),
            "raw HTML tags must not appear in output"
        );
    }

    #[test]
    fn renders_blockquote_with_style() {
        let html = render_markdown_excerpt("> Important note here");
        assert!(html.contains("blockquote"), "blockquote element expected");
        assert!(
            html.contains("border-left"),
            "blockquote should have border-left style"
        );
    }

    #[test]
    fn renders_code_block() {
        let html = render_markdown_excerpt("```\nsome code here\n```");
        assert!(html.contains("some code here"));
    }

    #[test]
    fn image_replaced_by_alt_text() {
        let html = render_markdown_excerpt("![screenshot of fix](https://example.com/img.png)");
        assert!(!html.contains("<img"), "img tags must not appear");
        assert!(html.contains("screenshot of fix"), "alt text should appear");
    }

    #[test]
    fn image_with_no_alt_text_dropped() {
        let html = render_markdown_excerpt("![](https://example.com/img.png)");
        assert!(!html.contains("<img"), "img tags must not appear");
    }

    #[test]
    fn renders_ordered_list() {
        let html = render_markdown_excerpt("1. First\n2. Second\n3. Third");
        assert!(html.contains("<ol"), "ordered list element expected");
        assert!(html.contains("First"));
        assert!(html.contains("Second"));
    }

    #[test]
    fn apply_email_styles_replaces_p_tag() {
        let styled = apply_email_styles("<p>hello</p>");
        assert!(
            styled.contains("margin:0 0 8px"),
            "p should get margin style"
        );
        assert!(styled.contains("hello"));
        assert!(!styled.contains("<p>"), "bare <p> should be replaced");
    }

    #[test]
    fn apply_email_styles_replaces_ul_and_li() {
        let styled = apply_email_styles("<ul><li>item</li></ul>");
        assert!(
            styled.contains("padding-left:18px"),
            "ul should get padding style"
        );
        assert!(
            styled.contains("margin-bottom:2px"),
            "li should get margin style"
        );
    }

    #[test]
    fn apply_email_styles_replaces_all_headings() {
        for tag in ["h1", "h2", "h3", "h4", "h5", "h6"] {
            let input = format!("<{tag}>Title</{tag}>");
            let styled = apply_email_styles(&input);
            assert!(
                styled.contains("font-weight:700"),
                "{tag} should get bold style"
            );
            assert!(
                !styled.contains(&format!("<{tag}>")),
                "bare {tag} should be replaced"
            );
        }
    }

    #[test]
    fn apply_email_styles_replaces_links() {
        let styled = apply_email_styles("<a href=\"x\">link</a>");
        assert!(
            styled.contains("color:#133A60"),
            "links should get color style"
        );
    }

    #[test]
    fn empty_body_renders_empty() {
        let html = render_markdown_excerpt("");
        assert!(
            html.is_empty() || !html.contains("…"),
            "empty body should not be truncated"
        );
    }

    #[test]
    fn renders_strikethrough() {
        let html = render_markdown_excerpt("~~removed~~");
        assert!(html.contains("removed"));
    }

    // ── is_top_level_block ────────────────────────────────────────────────────

    #[test]
    fn is_top_level_block_matches_all_block_types() {
        use pulldown_cmark::{CodeBlockKind, Tag};
        assert!(is_top_level_block(&Tag::Paragraph));
        assert!(is_top_level_block(&Tag::List(None)));
        assert!(is_top_level_block(&Tag::CodeBlock(CodeBlockKind::Fenced(
            "rust".into()
        ))));
        assert!(is_top_level_block(&Tag::BlockQuote(None)));
    }

    #[test]
    fn is_top_level_block_rejects_inline_tags() {
        use pulldown_cmark::Tag;
        assert!(!is_top_level_block(&Tag::Emphasis));
        assert!(!is_top_level_block(&Tag::Strong));
    }

    // ── is_top_level_block_end ────────────────────────────────────────────────

    #[test]
    fn is_top_level_block_end_matches_all_end_types() {
        use pulldown_cmark::{HeadingLevel, TagEnd};
        assert!(is_top_level_block_end(&TagEnd::Paragraph));
        assert!(is_top_level_block_end(&TagEnd::List(true)));
        assert!(is_top_level_block_end(&TagEnd::CodeBlock));
        assert!(is_top_level_block_end(&TagEnd::BlockQuote(None)));
        assert!(is_top_level_block_end(&TagEnd::Table));
        assert!(is_top_level_block_end(&TagEnd::Heading(HeadingLevel::H2)));
    }

    #[test]
    fn is_top_level_block_end_rejects_inline_ends() {
        use pulldown_cmark::TagEnd;
        assert!(!is_top_level_block_end(&TagEnd::Emphasis));
        assert!(!is_top_level_block_end(&TagEnd::Strong));
    }

    // ── build_client ──────────────────────────────────────────────────────────

    #[test]
    fn build_client_returns_some() {
        assert!(build_client().is_some());
    }

    // ── collect_first_blocks image branches ──────────────────────────────────

    #[test]
    fn image_in_image_non_text_events_are_dropped() {
        // An image followed by bold text inside alt — the bold markers should be dropped
        let html = render_markdown_excerpt("![**bold** alt](https://example.com/img.png)");
        assert!(!html.contains("<img"), "img must not appear");
        // The text content of the alt should appear
        assert!(html.contains("bold"), "alt text should appear");
    }
}
