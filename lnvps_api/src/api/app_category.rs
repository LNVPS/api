use std::collections::BTreeMap;

const TRANSLATIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "Nostr relay",
        &[
            ("ar", "خادم Nostr"),
            ("de", "Nostr-Relay"),
            ("es", "relé de Nostr"),
            ("fr", "relais Nostr"),
            ("ja", "Nostrリレー"),
            ("ko", "Nostr 릴레이"),
            ("pt", "relay Nostr"),
            ("ru", "ретранслятор Nostr"),
            ("tr", "Nostr rölesi"),
            ("zh", "Nostr 中继"),
        ],
    ),
    (
        "Community Nostr relay",
        &[
            ("ar", "خادم Nostr مجتمعي"),
            ("de", "Community-Nostr-Relay"),
            ("es", "relé de Nostr comunitario"),
            ("fr", "relais Nostr communautaire"),
            ("ja", "コミュニティ向けNostrリレー"),
            ("ko", "커뮤니티 Nostr 릴레이"),
            ("pt", "relay Nostr comunitário"),
            ("ru", "общественный ретранслятор Nostr"),
            ("tr", "topluluk Nostr rölesi"),
            ("zh", "社区 Nostr 中继"),
        ],
    ),
    (
        "Personal Nostr relay",
        &[
            ("ar", "خادم Nostr شخصي"),
            ("de", "Persönliches Nostr-Relay"),
            ("es", "relé de Nostr personal"),
            ("fr", "relais Nostr personnel"),
            ("ja", "個人用Nostrリレー"),
            ("ko", "개인용 Nostr 릴레이"),
            ("pt", "relay Nostr pessoal"),
            ("ru", "персональный ретранслятор Nostr"),
            ("tr", "kişisel Nostr rölesi"),
            ("zh", "个人 Nostr 中继"),
        ],
    ),
    (
        "Blossom media server",
        &[
            ("ar", "خادم وسائط Blossom"),
            ("de", "Blossom-Medienserver"),
            ("es", "servidor de medios Blossom"),
            ("fr", "serveur multimédia Blossom"),
            ("ja", "Blossomメディアサーバー"),
            ("ko", "Blossom 미디어 서버"),
            ("pt", "servidor de mídia Blossom"),
            ("ru", "медиасервер Blossom"),
            ("tr", "Blossom medya sunucusu"),
            ("zh", "Blossom 媒体服务器"),
        ],
    ),
    (
        "Self-hosted application",
        &[
            ("ar", "تطبيق مستضاف ذاتيًا"),
            ("de", "selbst gehostete Anwendung"),
            ("es", "aplicación autoalojada"),
            ("fr", "application auto-hébergée"),
            ("ja", "セルフホスト型アプリケーション"),
            ("ko", "셀프 호스팅 애플리케이션"),
            ("pt", "aplicação auto-hospedada"),
            ("ru", "самостоятельно размещаемое приложение"),
            ("tr", "kendi kendine barındırılan uygulama"),
            ("zh", "自托管应用"),
        ],
    ),
];

pub fn preferred_languages(accept_language: &str) -> Vec<String> {
    let mut ranked: Vec<(String, f32)> = accept_language
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.split(';');
            let tag = pieces.next()?.trim();
            if tag.is_empty() || tag == "*" {
                return None;
            }
            let q = pieces
                .find_map(|p| p.trim().strip_prefix("q=").map(str::to_string))
                .map(|v| v.trim().parse::<f32>().unwrap_or(0.0))
                .unwrap_or(1.0);
            if q <= 0.0 {
                return None;
            }
            let primary = tag.split(['-', '_']).next()?.to_ascii_lowercase();
            Some((primary, q))
        })
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
    ranked.into_iter().map(|(l, _)| l).collect()
}

pub fn parse_translations(raw: Option<&str>) -> BTreeMap<String, String> {
    raw.and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default()
}

pub fn localize_category(
    category: &str,
    stored: Option<&str>,
    accept_language: Option<&str>,
) -> String {
    let Some(header) = accept_language else {
        return category.to_string();
    };
    let stored = parse_translations(stored);
    let builtin = TRANSLATIONS
        .iter()
        .find(|(en, _)| *en == category)
        .map(|(_, by_lang)| *by_lang);
    for lang in preferred_languages(header) {
        if lang == "en" {
            break;
        }
        if let Some(text) = stored.get(&lang) {
            return text.clone();
        }
        if let Some((_, text)) = builtin.and_then(|b| b.iter().find(|(l, _)| *l == lang)) {
            return text.to_string();
        }
    }
    category.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALES: [&str; 10] = ["ar", "de", "es", "fr", "ja", "ko", "pt", "ru", "tr", "zh"];

    #[test]
    fn every_category_has_all_ten_locales() {
        for (en, by_lang) in TRANSLATIONS {
            for l in LOCALES {
                assert!(
                    by_lang.iter().any(|(k, v)| *k == l && !v.is_empty()),
                    "{en} missing {l}"
                );
            }
        }
    }

    #[test]
    fn serves_translated_category_for_accept_language() {
        assert_eq!(
            localize_category("Nostr relay", None, Some("de-DE,de;q=0.9,en;q=0.8")),
            "Nostr-Relay"
        );
        assert_eq!(
            localize_category("Blossom media server", None, Some("ru")),
            "медиасервер Blossom"
        );
    }

    #[test]
    fn falls_back_to_english() {
        assert_eq!(localize_category("Nostr relay", None, None), "Nostr relay");
        assert_eq!(
            localize_category("Nostr relay", None, Some("en-US")),
            "Nostr relay"
        );
        assert_eq!(
            localize_category("Nostr relay", None, Some("it")),
            "Nostr relay"
        );
        assert_eq!(
            localize_category("Git server", None, Some("de")),
            "Git server"
        );
    }

    #[test]
    fn stored_translation_beats_builtin_and_covers_new_categories() {
        let stored = Some(r#"{"de":"Git-Server","fr":"serveur Git"}"#);
        assert_eq!(
            localize_category("Git server", stored, Some("de")),
            "Git-Server"
        );
        assert_eq!(
            localize_category("Git server", stored, Some("ja")),
            "Git server"
        );
        assert_eq!(
            localize_category("Nostr relay", Some(r#"{"de":"Relay"}"#), Some("de")),
            "Relay"
        );
        assert_eq!(
            localize_category("Nostr relay", Some(r#"{"de":"Relay"}"#), Some("fr")),
            "relais Nostr"
        );
    }

    #[test]
    fn malformed_stored_translations_fall_back() {
        assert_eq!(
            localize_category("Nostr relay", Some("not json"), Some("de")),
            "Nostr-Relay"
        );
    }

    #[test]
    fn honours_quality_order() {
        assert_eq!(
            localize_category("Nostr relay", None, Some("fr;q=0.4, ja;q=0.9")),
            "Nostrリレー"
        );
        assert_eq!(
            localize_category("Nostr relay", None, Some("en, de;q=0.5")),
            "Nostr relay"
        );
    }
}
