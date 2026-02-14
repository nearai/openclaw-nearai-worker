use rand::prelude::IndexedRandom;

const ADJECTIVES: &[&str] = &[
    "bold", "brave", "bright", "calm", "clever", "cool", "crisp", "dark", "eager", "fair", "fast",
    "fierce", "firm", "fresh", "glad", "grand", "green", "happy", "keen", "kind", "lively",
    "lucky", "merry", "mighty", "neat", "noble", "pale", "plain", "proud", "pure", "quick",
    "quiet", "rapid", "rare", "rich", "rough", "sharp", "shy", "sleek", "slim", "smart", "smooth",
    "soft", "solid", "stark", "steel", "still", "swift", "tall", "warm", "wild", "wise",
];

const NOUNS: &[&str] = &[
    "ant", "ape", "bat", "bear", "bee", "bird", "boar", "bull", "cat", "colt", "crab", "crow",
    "deer", "dove", "duck", "eagle", "elk", "fawn", "fish", "fly", "fox", "frog", "goat", "goose",
    "gull", "hare", "hawk", "hen", "horse", "jay", "lark", "lion", "lynx", "mole", "moth", "mule",
    "newt", "orca", "owl", "panda", "pike", "pony", "ram", "robin", "seal", "snake", "swan",
    "tiger", "toad", "viper", "wasp", "whale", "wolf",
];

/// Generate a random friendly name like "brave-tiger".
/// Calls `exists` to check for collisions and retries up to 10 times.
pub fn generate_name(exists: impl Fn(&str) -> bool) -> Option<String> {
    let mut rng = rand::rng();
    for _ in 0..10 {
        let adj = ADJECTIVES.choose(&mut rng)?;
        let noun = NOUNS.choose(&mut rng)?;
        let name = format!("{}-{}", adj, noun);
        if !exists(&name) {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_name_format() {
        let name = generate_name(|_| false).unwrap();
        assert!(name.contains('-'));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(ADJECTIVES.contains(&parts[0]));
        assert!(NOUNS.contains(&parts[1]));
    }

    #[test]
    fn test_generate_name_avoids_collisions() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        // Reject the first attempt, accept the second
        let name = generate_name(|_| attempts.fetch_add(1, Ordering::Relaxed) == 0);
        assert!(name.is_some());
        assert!(attempts.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn test_generate_name_returns_none_when_exhausted() {
        // Always say name exists → should return None after retries
        let result = generate_name(|_| true);
        assert!(result.is_none());
    }
}
