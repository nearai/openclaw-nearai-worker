use rand::prelude::IndexedRandom;

const ADJECTIVES: &[&str] = &[
    "bold", "brave", "bright", "calm", "clever", "cool", "crisp", "dark",
    "eager", "fair", "fast", "fierce", "firm", "fresh", "glad", "grand",
    "green", "happy", "keen", "kind", "lively", "lucky", "merry", "mighty",
    "neat", "noble", "pale", "plain", "proud", "pure", "quick", "quiet",
    "rapid", "rare", "rich", "rough", "sharp", "shy", "sleek", "slim",
    "smart", "smooth", "soft", "solid", "stark", "steel", "still", "swift",
    "tall", "warm", "wild", "wise",
];

const NOUNS: &[&str] = &[
    "ant", "ape", "bat", "bear", "bee", "bird", "boar", "bull", "cat",
    "colt", "crab", "crow", "deer", "dove", "duck", "eagle", "elk", "fawn",
    "fish", "fly", "fox", "frog", "goat", "goose", "gull", "hare", "hawk",
    "hen", "horse", "jay", "lark", "lion", "lynx", "mole", "moth", "mule",
    "newt", "orca", "owl", "panda", "pike", "pony", "ram", "robin", "seal",
    "snake", "swan", "tiger", "toad", "viper", "wasp", "whale", "wolf",
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
