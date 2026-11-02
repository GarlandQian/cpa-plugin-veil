# User names and public IP addresses go upstream as Stand-ins

Every other Kind goes upstream as a `{{KIND_xxxxxxxx}}` Placeholder, but a user name goes as eight made-up lowercase letters and a public IP address as `public-ip-` and eight made-up lowercase letters, both derived from the same key and Caller scope as Placeholders. magpie learned this from incidents: a model read `C:\Users\{{USERNAME_…}}` as a temporary folder and set out to delete the user's home; told a server was `{{IP_…}}`, models asked the user for the real address, and an address from the documentation ranges was recognised as an example. With a home folder that still looks like one and a host name with no dot that reaches no one, models use the value as is, and it comes back restored in the tool call.

## Consequences

- A Stand-in can collide with a real word or another value; Veil tries up to eight candidates and falls back to a Placeholder.
- Stand-ins restore case-insensitively, the IP ones only as a whole word, and the streaming Held tail has to recognise the start of any Stand-in live in the Caller scope.
