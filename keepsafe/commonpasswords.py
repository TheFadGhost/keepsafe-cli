"""Small embedded common-password blocklist used by the audit command.

Provenance: compiled locally from public common-password research lists
(e.g. the SecLists top-common set and leaked-corpus frequency rankings),
embedded as literals on purpose so the audit runs fully offline. There
are no network lookups of any kind, now or ever; see PLAN.md (breach-
database lookup rejected). Membership is checked on the lowercased
secret, so entries here are lowercase by definition.
"""

from __future__ import annotations

COMMON_PASSWORDS: frozenset[str] = frozenset({
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "1234567890", "0987654321", "987654321", "111111", "000000",
    "121212", "112233", "123123", "654321", "696969", "666666",
    "88888888", "159753", "147258369", "qwerty", "qwertyuiop",
    "qwerty123", "qwe123", "123qwe", "1q2w3e4r", "1qaz2wsx",
    "zaq12wsx", "qazwsx", "qazwsxedc", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "abc123", "abc123456", "qwer1234",
    "1234qwer", "password", "password1", "password123", "passw0rd",
    "p@ssword", "p@ssw0rd", "pa55word", "pa55w0rd", "passwd",
    "pass", "pass123", "mypassword", "newpassword", "michael",
    "jennifer", "jordan", "jordan23", "jessica", "nicole",
    "daniel", "matthew", "ashley", "joshua", "amanda", "anthony",
    "andrew", "charlie", "george", "thomas", "robert", "william",
    "michelle", "sarah", "stephanie", "christopher", "alexander",
    "brandon", "justin", "kevin", "jason", "hannah", "megan",
    "lauren", "samantha", "monkey", "dragon", "tiger", "lion",
    "bear", "wolf", "eagle", "falcon", "hawk", "panther", "jaguar",
    "dolphin", "turtle", "butterfly", "spider", "scorpion",
    "phoenix", "wizard", "shadow", "tigger", "snoopy", "buster",
    "jasper", "ginger", "cookie", "barney", "bailey", "player",
    "ranger", "harley", "hunter", "killer", "ninja", "mustang",
    "football", "baseball", "basketball", "soccer", "hockey",
    "liverpool", "arsenal", "chelsea", "barcelona", "realmadrid",
    "juventus", "yankees", "lakers", "cowboys", "packers",
    "steelers", "eagles", "starwars", "pokemon", "pikachu",
    "slipknot", "metallica", "eminem", "nirvana", "blink182",
    "myspace1", "superman", "batman", "spiderman", "letmein",
    "welcome", "welcome1", "hello", "freedom", "whatever",
    "trustno1", "sunshine", "master", "secret", "changeme",
    "love", "summer", "winter", "spring", "flower", "honey",
    "banana", "cheese", "coffee", "chocolate", "chicken",
    "purple", "orange", "silver", "gold", "diamond", "money",
    "angel", "jesus", "sexy", "sex", "pepper", "maggie", "butter",
    "computer", "google", "facebook", "samsung", "nokia", "apple",
    "iphone", "android", "minecraft", "admin", "admin123",
    "administrator", "root", "toor", "login", "guest", "user",
    "test", "default",
})
