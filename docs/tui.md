# Terminal UI

```sh
cvedex tui
```

A full-screen view of your CVE IDs. Open a record, write it in your editor, reserve IDs, without leaving the terminal.

```
 cvedex   CVE IDs                                https://cveawg-test.mitre.org · alice@acme.org

 CVE ID            STATE        RESERVED      BY
 CVE-2026-1099     PUBLISHED    2026-10-22    alice@acme.org
 CVE-2026-1100     PUBLISHED    2026-10-22    alice@acme.org
 CVE-2026-1101     RESERVED     2026-10-22    alice@acme.org

 ↑↓ move · enter open · e edit · n new ID · r refresh · q quit
```

## Keys

| Key | Does |
| --- | --- |
| ++up++ ++down++ | Move, or scroll a record |
| ++enter++ | Open the record |
| ++esc++ | Back to the list |
| ++e++ | Edit the record in your editor |
| ++n++ | Reserve a new ID for this year |
| ++r++ | Refresh |
| ++tab++ / ++1++ ++2++ ++3++ | Switch tab, on cvedexd |
| ++q++ | Quit |

Every write asks `y/n` first.

## Edit a record

Press ++e++ on an ID. `cvedex` opens its record in `$VISUAL`, or `$EDITOR`, or `vi`:

- **A reserved ID** opens a template with the fields CVE Services requires.
- **A published ID** opens its CNA container, without the `providerMetadata` CVE Services fills in.

Save and close the editor. `cvedex` asks to publish or update. Close without changes and nothing is sent.

```sh
EDITOR="code --wait" cvedex tui
```

!!! tip "A rejected draft is kept"
    If CVE Services rejects the record, the TUI shows its errors under the list. Press ++e++ again and your draft reopens with your edits, not the original.

## On cvedexd

Against a [cvedexd](cvedexd/index.md) server, the TUI shows the tabs your role allows:

| You are | Tabs | Keys |
| --- | --- | --- |
| A CNA user | CVE IDs, Review, Audit | ++enter++ read and ++a++ approve a record in review |
| A submitter | CVE IDs, Proposals | ++a++ approve or ++d++ deny an agent's proposal |

A submitter's IDs show `changes requested` when a reviewer sent the record back. Move to the ID to see the reviewer's note.
