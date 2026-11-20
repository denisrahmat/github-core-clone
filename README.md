# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/denisrahmat/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/denisrahmat/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge in a single Node 22 process: git smart HTTP (upload-pack v2, receive-pack v0), the REST v3 API, GraphQL v4 and MCP, all served from its own in-memory store. No UI, no git binary, no outside service. Local kit runner: 120/120 checks, 987/1000.

## Run it

```sh
MAKEFUN_ENV_URL=http://store:8080 MAKEFUN_SHOP_TOKEN=$TOKEN node --experimental-strip-types main.ts
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=1c2dm2fm&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
