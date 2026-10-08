# GHOST PROTOCOL — COMMAND CONSOLE & NATURAL LANGUAGE REFERENCE

This document lists all slash commands and natural language query examples supported by the **GHOST Command Console (`GHOST>`)**.

---

## 1. Slash Commands

| Command | Action | Description |
| :--- | :--- | :--- |
| `/help` | `help` | Displays command reference, slash options, and available intents. |
| `/status` | `status` | Returns system status, active sources count, Whonix gateway state, and model status. |
| `/sources` | `sources` | Lists registered sources, URLs, collector types, environment, and validation states. |
| `/add-source <url>` | `add_source` | Registers a new target URL (real-world onion/web or synthetic docker lab) into `source_registry.db`. |
| `/sherlock <username>` | `run_sherlock` | Executes OSINT handle discovery across synthetic lab services and known platforms. |
| `/observe <url>` | `observe_source` | Registers and observes target URL immediately. |
| `/capture` | `capture_current_source` | Captures immediate observation pass over current targeted source. |
| `/search <query>` | `search_history` | Searches historical observation store or Ahmia for query string. |
| `/history <entity>`| `search_history` | Returns historical observation records matching entity. |
| `/timeline <entity>`| `get_entity_timeline` | Generates longitudinal timeline for actor/target entity. |
| `/correlate <entity>`| `find_entity` | Runs composite entity resolution and graph correlation. |
| `/deep-analyze` | `deep_analyze` | Executes full ML, CTI, STIX, MITRE, and XAI deep analysis pipeline. |
| `/explain` | `get_model_explanation` | Returns XAI decision narrative explanation. |

---

## 2. Natural Language Query Examples

The local cyber dictionary parser (`src/config/ghost_dictionary.json`) matches natural language analyst queries to local function dispatches:

### Source Lifecycle & Availability
- `"what happened to this site?"` → Retrieves source observation history & change state.
- `"when did it go down?"` → Returns source status timeline and offline events.
- `"when was this source last online?"` → Queries last successful observation timestamp.

### Actor & Entity Investigation
- `"where have we seen ViperSec?"` → Runs entity correlation for handle `ViperSec`.
- `"where has Viper_X appeared?"` → Searches historical memory for handle `Viper_X`.
- `"what is this person doing?"` → Generates actor timeline and post history.
- `"show me everything related to ApexGlobal"` → Correlates victim organization `ApexGlobal Financial`.

### Threat & Infrastructure Search
- `"find ransomware posts"` → Searches history store for threat category `RANSOMWARE`.
- `"which sources mention this onion?"` → Searches observation records for `.onion` URL match.
- `"search ahmia for stolen data"` → Formulates Ahmia query for candidate onion discovery.

### Model & XAI Evidence
- `"why was this flagged?"` → Retrieves DistilBERT prediction, confidence, token highlights, and XAI summary.
- `"deep analyze this"` → Runs deep analysis pipeline over latest observation.
- `"capture this"` → Captures immediate observation pass over targeted source.
