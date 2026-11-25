//! Finding exit nodes: the adverts exits publish on Nostr.
//!
//! An exit that wants to be found publishes one event, signed with its own
//! fips key (`exit-node/advert.py`, where the format is specified). A fips
//! identity is a Nostr key, so the advert's author IS the exit: the npub
//! this module hands to the app is the one the node will route to, and
//! nobody else can advertise that exit. That is all an advert proves. Its
//! name and note are whatever the operator typed, and "open" is a claim.
//!
//! Where it looks:
//!
//! - The **mesh relays** from Settings (`names_mesh_relays`,
//!   `ws://<npub>.fips`), each through its own loopback listener
//!   ([`MeshRelayProxy`]) for the length of one search. These answer with no
//!   internet at all, which is the case the feature exists for.
//! - The **public relays**, only while Android reports a validated Internet:
//!   without one they would only be waited for.
//!
//! Only ever on request (the Internet route screen's button): asking a
//! public relay for exit adverts tells it that this address is looking for
//! an exit.
//!
//! Nothing found here is used by itself. The app lists it; the user adds an
//! exit and then selects it, as with one typed by hand.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::meshhttp::MeshLink;
use crate::meshtcp::MeshRelayProxy;

/// NIP-78 application data; see `exit-node/advert.py`.
const KIND: u16 = 30078;
const D_TAG: &str = "fips-exit";
/// The wire contract this app speaks (`exit.rs`): adverts of another are
/// not listed, since selecting such an exit would only block traffic.
const VERSION: &str = "1";
const MAX_NAME: usize = 40;
const MAX_ABOUT: usize = 200;
/// Adverts listed at most. Anyone can publish one; the list is for a person.
pub const MAX_ADVERTS: usize = 100;
/// An advert may be dated this far ahead (clock differences), and may not
/// claim to be valid for longer than this.
const MAX_SKEW_SECS: u64 = 600;
const MAX_LIFETIME_SECS: u64 = 31 * 86400;

/// One exit's advert, as the app shows it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Advert {
    pub npub: String,
    /// The operator's name for it, possibly empty.
    pub name: String,
    /// The operator's note, possibly empty.
    pub about: String,
    /// `"open"` or `"allow-list"`: what the operator says.
    pub access: String,
    /// Unix seconds the advert was made, and until when it is valid.
    pub created_at: u64,
    pub expires: u64,
}

/// A received event, reduced to what [`advert_of`] reads. Its signature has
/// been checked by then.
pub struct Raw {
    pub npub: String,
    pub kind: u16,
    pub created_at: u64,
    pub tags: Vec<Vec<String>>,
}

/// Operator text for a list on a phone: one line, no control characters
/// (they could reorder or hide what is shown next to it), bounded.
fn tidy(text: &str, limit: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !is_format_control(*c))
        .collect();
    let words: Vec<&str> = cleaned.split(' ').filter(|w| !w.is_empty()).collect();
    words.join(" ").chars().take(limit).collect()
}

/// Bidirectional and invisible formatting characters: an "about" must not
/// be able to rearrange the line it is shown on.
fn is_format_control(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// The advert in `raw`, if it is one this app can use now: the right kind
/// and marker, this app's contract version, a known access word, and valid
/// at `now`. `None` for anything else — an advert is untrusted input, and
/// one that is odd is not shown rather than half shown.
pub fn advert_of(raw: &Raw, now: u64) -> Option<Advert> {
    if raw.kind != KIND || raw.created_at > now + MAX_SKEW_SECS {
        return None;
    }
    let tag = |name: &str| {
        raw.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    };
    if tag("d") != Some(D_TAG) || tag("v") != Some(VERSION) {
        return None;
    }
    let access = tag("access")?;
    if access != "open" && access != "allow-list" {
        return None;
    }
    // No expiration, or one already past: an exit that stopped advertising
    // is gone. One absurdly far ahead is not believed either.
    let expires: u64 = tag("expiration")?.parse().ok()?;
    if expires <= now || expires > now + MAX_LIFETIME_SECS {
        return None;
    }
    Some(Advert {
        npub: raw.npub.clone(),
        name: tidy(tag("name").unwrap_or(""), MAX_NAME),
        about: tidy(tag("about").unwrap_or(""), MAX_ABOUT),
        access: access.to_string(),
        created_at: raw.created_at,
        expires,
    })
}

/// The list to show: one advert per exit (its newest), never this node's
/// own, open exits first and then the most recently published, at most
/// [`MAX_ADVERTS`].
pub fn select(raws: &[Raw], own_npub: &str, now: u64) -> Vec<Advert> {
    let mut newest: HashMap<&str, Advert> = HashMap::new();
    for raw in raws {
        if raw.npub == own_npub {
            continue;
        }
        let Some(advert) = advert_of(raw, now) else {
            continue;
        };
        match newest.get(raw.npub.as_str()) {
            Some(have) if have.created_at >= advert.created_at => {}
            _ => {
                newest.insert(raw.npub.as_str(), advert);
            }
        }
    }
    let mut list: Vec<Advert> = newest.into_values().collect();
    list.sort_by(|a, b| {
        (b.access == "open")
            .cmp(&(a.access == "open"))
            .then(b.created_at.cmp(&a.created_at))
            .then(a.npub.cmp(&b.npub))
    });
    list.truncate(MAX_ADVERTS);
    list
}

/// What a search asked and found.
#[derive(Debug, serde::Serialize)]
pub struct Found {
    pub exits: Vec<Advert>,
    /// Relays asked, by kind: so the app can say "no mesh relay is set"
    /// instead of "nothing found".
    pub mesh_relays: usize,
    pub public_relays: usize,
}

/// Ask the relays for exit adverts. Blocking, up to about `timeout`.
/// `mesh_relays` are `ws://<npub>.fips…` URLs; `public_relays` are asked
/// only when `online`.
pub fn find(
    link: &Arc<MeshLink>,
    mesh_relays: &[String],
    public_relays: &[String],
    online: bool,
    own_npub: &str,
    timeout: Duration,
) -> Result<Found, String> {
    // The listeners live for this search only.
    let proxies: Vec<MeshRelayProxy> = mesh_relays
        .iter()
        .filter_map(|url| match MeshRelayProxy::start(link.clone(), url) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(error = %e, "mesh relay not asked for exit adverts");
                None
            }
        })
        .collect();
    let mut urls: Vec<String> = proxies.iter().map(|p| p.local_url.clone()).collect();
    let mesh_count = urls.len();
    let public: &[String] = if online { public_relays } else { &[] };
    urls.extend(public.iter().cloned());
    if urls.is_empty() {
        return Ok(Found {
            exits: Vec::new(),
            mesh_relays: 0,
            public_relays: 0,
        });
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let raws = rt.block_on(fetch(&urls, timeout));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exits = select(&raws, own_npub, now);
    tracing::info!(
        mesh_relays = mesh_count,
        public_relays = public.len(),
        events = raws.len(),
        exits = exits.len(),
        "looked for exit adverts"
    );
    Ok(Found {
        exits,
        mesh_relays: mesh_count,
        public_relays: public.len(),
    })
}

async fn fetch(urls: &[String], timeout: Duration) -> Vec<Raw> {
    let client = Client::default();
    for url in urls {
        // A relay the library will not take is one relay fewer, not a
        // failed search.
        if let Err(e) = client.add_relay(url.as_str()).await {
            tracing::debug!(error = %e, "relay not asked for exit adverts");
        }
    }
    client.connect().await;
    let filter = Filter::new()
        .kind(Kind::from(KIND))
        .identifier(D_TAG)
        // More than is shown: several relays hold the same adverts, and
        // expired ones are still stored by relays that ignore NIP-40.
        .limit(MAX_ADVERTS * 4);
    let events = match client.fetch_events(filter, timeout).await {
        Ok(events) => events,
        Err(e) => {
            tracing::debug!(error = %e, "no exit adverts fetched");
            Events::default()
        }
    };
    let raws = events
        .into_iter()
        // The pool verifies; this is the line that must not be lost if that
        // ever changes: an advert is only its signature.
        .filter(|e| e.verify().is_ok())
        .filter_map(|e| {
            Some(Raw {
                npub: e.pubkey.to_bech32().ok()?,
                kind: e.kind.as_u16(),
                created_at: e.created_at.as_secs(),
                tags: e.tags.iter().map(|t| t.as_slice().to_vec()).collect(),
            })
        })
        .collect();
    client.shutdown().await;
    raws
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ME: &str = "npub1me";

    fn raw(npub: &str, created_at: u64, tags: &[&[&str]]) -> Raw {
        Raw {
            npub: npub.to_string(),
            kind: KIND,
            created_at,
            tags: tags
                .iter()
                .map(|t| t.iter().map(|s| s.to_string()).collect())
                .collect(),
        }
    }

    /// A well-formed advert with one tag replaced, added or (`value` None)
    /// removed.
    fn with(tag: &str, value: Option<&str>) -> Raw {
        let expires = (NOW + 3600).to_string();
        let mut tags: Vec<Vec<String>> = [
            ["d", D_TAG],
            ["v", "1"],
            ["access", "open"],
            ["name", "My exit"],
            ["about", "Zurich"],
            ["expiration", &expires],
        ]
        .iter()
        .map(|t| t.iter().map(|s| s.to_string()).collect())
        .collect();
        tags.retain(|t| t[0] != tag);
        if let Some(v) = value {
            tags.push(vec![tag.to_string(), v.to_string()]);
        }
        Raw {
            npub: "npub1exit".into(),
            kind: KIND,
            created_at: NOW - 60,
            tags,
        }
    }

    #[test]
    fn a_well_formed_advert_is_read() {
        let a = advert_of(&with("", None), NOW).unwrap();
        assert_eq!(
            a,
            Advert {
                npub: "npub1exit".into(),
                name: "My exit".into(),
                about: "Zurich".into(),
                access: "open".into(),
                created_at: NOW - 60,
                expires: NOW + 3600,
            }
        );
        let a = advert_of(&with("access", Some("allow-list")), NOW).unwrap();
        assert_eq!(a.access, "allow-list");
        // Name and note are optional.
        let a = advert_of(&with("name", None), NOW).unwrap();
        assert_eq!(a.name, "");
    }

    #[test]
    fn anything_odd_is_not_shown() {
        let past = (NOW - 1).to_string();
        let far = (NOW + 60 * 86400).to_string();
        for (tag, value) in [
            ("d", Some("something-else")),
            ("d", None),
            ("v", Some("2")),
            ("v", None),
            ("access", Some("paid")),
            ("access", None),
            ("expiration", None),
            ("expiration", Some(past.as_str())),
            ("expiration", Some(far.as_str())),
            ("expiration", Some("soon")),
        ] {
            assert_eq!(advert_of(&with(tag, value), NOW), None, "{tag} = {value:?}");
        }
        let mut other_kind = with("", None);
        other_kind.kind = 1;
        assert_eq!(advert_of(&other_kind, NOW), None);
        let mut from_the_future = with("", None);
        from_the_future.created_at = NOW + 3600;
        assert_eq!(advert_of(&from_the_future, NOW), None);
    }

    /// The operator's text ends up on a line in a list: one line, bounded,
    /// and unable to rearrange what stands next to it.
    #[test]
    fn operator_text_is_tidied() {
        assert_eq!(tidy("  two\n\tlines  here ", 40), "two lines here");
        assert_eq!(tidy("bell\u{7}and\u{0}null", 40), "bellandnull");
        assert_eq!(tidy("abc\u{202E}dcba", 40), "abcdcba", "no right-to-left override");
        assert_eq!(tidy("zero\u{200B}width", 40), "zerowidth");
        assert_eq!(tidy(&"x".repeat(500), MAX_NAME).chars().count(), MAX_NAME);
        assert_eq!(tidy("Zürich ☕", 40), "Zürich ☕");
        let a = advert_of(&with("about", Some(&"é".repeat(1000))), NOW).unwrap();
        assert_eq!(a.about.chars().count(), MAX_ABOUT);
    }

    #[test]
    fn the_list_has_one_advert_per_exit_open_first_and_never_ourselves() {
        let exp = (NOW + 3600).to_string();
        let advert = |npub: &str, at: u64, access: &str, name: &str| {
            raw(
                npub,
                at,
                &[
                    &["d", D_TAG],
                    &["v", "1"],
                    &["access", access],
                    &["name", name],
                    &["expiration", &exp],
                ],
            )
        };
        let raws = vec![
            advert("npub1a", NOW - 500, "allow-list", "old a"),
            advert("npub1a", NOW - 100, "allow-list", "new a"),
            advert("npub1b", NOW - 900, "open", "b"),
            advert("npub1c", NOW - 50, "open", "c"),
            advert(ME, NOW - 10, "open", "this phone"),
            raw("npub1junk", NOW - 10, &[&["d", D_TAG]]),
        ];
        let list = select(&raws, ME, NOW);
        let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["c", "b", "new a"]);
    }

    /// Against a real relay holding adverts from `exit-node/advert.py`: set
    /// `EXITFIND_RELAY=ws://127.0.0.1:10547` (e.g. `nak serve`) and run
    /// `cargo test exitfind::tests::reads_adverts_from_a_relay -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn reads_adverts_from_a_relay() {
        let url = std::env::var("EXITFIND_RELAY").expect("EXITFIND_RELAY");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let raws = rt.block_on(fetch(&[url], Duration::from_secs(5)));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let list = select(&raws, ME, now);
        println!("EVENTS {} ADVERTS {}", raws.len(), serde_json::to_string(&list).unwrap());
        assert!(!list.is_empty(), "no advert read from the relay");
    }

    #[test]
    fn the_list_is_bounded() {
        let exp = (NOW + 3600).to_string();
        let raws: Vec<Raw> = (0..MAX_ADVERTS + 50)
            .map(|i| {
                raw(
                    &format!("npub1{i}"),
                    NOW - 100,
                    &[
                        &["d", D_TAG],
                        &["v", "1"],
                        &["access", "open"],
                        &["expiration", &exp],
                    ],
                )
            })
            .collect();
        assert_eq!(select(&raws, ME, NOW).len(), MAX_ADVERTS);
    }
}
