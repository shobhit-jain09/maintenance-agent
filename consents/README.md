# Standing consent files

The agent never accesses a repository until a person authorises it. For **manual** runs you authorise at run time
(type the repo name in the `confirm` box). For **scheduled** runs there is nobody at the keyboard, so you leave a
**standing consent file** here. It names the repository, the permissions, who granted it, and **expires automatically**
(maximum 90 days).

Create one (shows you the access notice, then asks you to type the repository name):

```bash
python -m agent consent grant https://github.com/<owner>/<name> --scopes read,execute --days 30 --out consents/target.yml
git add consents/target.yml && git commit -m "Grant maintenance-agent access to <owner>/<name> for 30 days"
```

Committing it to the **agent repo** gives you an audit trail (who granted it, when). Never put it in the repository being
analysed (the agent refuses a consent file found there). Delete the file to revoke. When it expires, scheduled runs stop
until you grant again.

Scopes: `read` (read source), `execute` (run its tests in the sandbox), `llm` (send redacted snippets to an LLM),
`write` (push an `agent/*` branch and open a PR; only possible if you have write access to the repo).
