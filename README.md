# Drost Community Edition

**The open-source, container-native MCP security toolkit from Drost.**

[Drost](https://www.drost.ai/) · [Drost Edge](https://edge.drost.ai/) · [Drost Elite](https://www.drost.ai/elite) · [Apache-2.0](LICENSE)

Drost Community Edition is the public release of **Drost-v1**: one Kali-based
Docker image containing an MCP server, 105 executable-backed security tools,
and 23 Drost-native tools for agent-driven and operator-driven security work.

It runs over stdio, publishes no network service, and works with Tess and other
MCP clients that can launch a local command. Images can be built for
\`linux/amd64\` and \`linux/arm64\`, including Apple Silicon hosts through
Docker Desktop.

> Use Drost only against systems you own or are explicitly authorized to test.
> The software provides capability, not permission.

## Where Drost began

Drost has gone through four major architectural generations:

1. **Drost-v1 — Community Edition:** the container-native MCP security toolkit
   released in this repository.
2. **Drost-v2 — Drost Edge:** customer-controlled autonomous security from the
   terminal.
3. **Drost-v3 — Drost Platform:** hosted autonomous assessment with a recursive
   self-improvement loop.
4. **Drost-v4 — Drost Swarm:** coordinated offensive agents combined with human
   judgment, represented commercially by Drost Elite.

Each generation introduced a different operating model and a substantial
capability jump. Community Edition is not a copy of the closed-source Drost
products and does not contain their proprietary runtimes, orchestration,
control planes, or multi-agent systems. It is a useful, extensible release of
the original Drost foundation.

## What is included

- **128 MCP tools:** 105 executable-backed tools and 23 Drost-native tools.
- **One container:** the MCP server and its security executables share the same
  Kali-based image.
- **Direct stdio transport:** no HTTP API, listening port, or separate worker
  service.
- **Compact and full MCP modes:** attach a small native tool surface or expose
  every executable as an individual MCP tool.
- **Persistent workspace:** engagement inputs and outputs live under
  \`/workspace\`.
- **Multi-architecture builds:** one Dockerfile for \`linux/amd64\` and
  \`linux/arm64\`.
- **Client-owned execution limits:** Drost does not impose artificial execution
  timeouts or truncate tool output. The MCP client controls its request
  deadlines, cancellation, and context handling.
- **Explicit process execution:** executable arguments are passed as an array
  with \`shell=False\`.

## Tool coverage

The executable-backed catalog includes:

| Family | Tools | Examples |
| --- | ---: | --- |
| Network | 10 | Nmap, RustScan, Masscan, tcpdump, TShark |
| Enumeration and OSINT | 16 | Amass, Subfinder, enum4linux-ng, NetExec |
| Web and API | 30 | Nuclei, HTTPX, FFUF, SQLMap, Katana, Dalfox |
| Credentials | 8 | Hydra, John the Ripper, Hashcat |
| Exploitation | 3 | Metasploit, Msfvenom, SearchSploit |
| Binary analysis | 14 | GDB, Ghidra, Radare2, checksec, Pwntools |
| Forensics | 11 | Volatility, Foremost, ExifTool, Sleuth Kit |
| Cloud, containers, and IaC | 8 | Prowler, Trivy, Checkov, kube-bench |
| Wireless | 5 | Aircrack-ng, Airmon-ng, Airodump-ng, Kismet |

Drost-native tools add catalog discovery, controlled execution, workspace
operations, HTTP and GraphQL requests, JWT and OpenAPI inspection, CVE lookup,
file hashing, indicator extraction, engagement planning, tool recommendations,
attack-chain organization, and scan summaries.

Use \`drost_catalog\` for the live catalog and input contracts.

## Architecture

\`\`\`text
MCP client
    |
    | stdio
    v
docker exec -i drost-ai drost-mcp
    |
    +-- Drost-native tool
    |
    +-- catalog adapter --> executable inside the container
    |
    +-- /workspace       --> persistent engagement artifacts
\`\`\`

The server publishes no ports. The persistent container is simply the
execution environment in which the client starts \`drost-mcp\`.

## Quick start

Requirements:

- Docker Engine or Docker Desktop
- An MCP client such as Tess

Build and start the persistent container:

\`\`\`sh
docker build -t drost-ai:local .
docker run -d \
  --name drost-ai \
  --restart unless-stopped \
  -v drost-ai-workspace:/workspace \
  drost-ai:local
\`\`\`

Verify the MCP installation:

\`\`\`sh
docker exec drost-ai drost-mcp --self-test
\`\`\`

The container deliberately publishes no host ports.

## Connect Tess

Run this from the project in which Tess should store its local MCP
registration:

\`\`\`sh
tess mcp add --scope local drost-ai docker -- \
  exec -i -e DROST_MCP_MODE=compact drost-ai drost-mcp
\`\`\`

Restart Tess after registration. Then ask it to call \`drost_catalog\`, choose
an authorized tool, and execute it.

Compact mode exposes the Drost-native workflow tools and keeps the complete
executable catalog available through \`drost_catalog\` and \`drost_execute\`.
Remove \`-e DROST_MCP_MODE=compact\` to expose all 128 tools directly.

## Connect another MCP client

Clients that accept the common \`mcpServers\` configuration shape can use:

\`\`\`json
{
  "mcpServers": {
    "drost": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "-e",
        "DROST_MCP_MODE=compact",
        "drost-ai",
        "drost-mcp"
      ]
    }
  }
}
\`\`\`

The exact configuration file and restart procedure depend on the MCP client.

## Build both architectures

Validate one architecture locally:

\`\`\`sh
docker buildx build \
  --platform linux/amd64 \
  --progress=plain \
  -t drost-ai:amd64 \
  --load .
\`\`\`

Build a multi-architecture manifest after selecting a registry:

\`\`\`sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t REGISTRY/drost-community:1.0.0 \
  --push .
\`\`\`

No registry image is published by this repository yet.

## Development

Run the unit tests from a source checkout:

\`\`\`sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
\`\`\`

The Docker smoke test exercises MCP initialization, tool discovery, a
representative tool call, and container behavior:

\`\`\`sh
python3 tests/mcp_smoke.py
\`\`\`

Contributions that improve tool coverage, schemas, portability, documentation,
or test quality are welcome. Keep tool execution explicit, preserve stdio MCP
behavior, and include tests for behavioral changes.

## Responsible use

Drost Community Edition invokes real security tools. Depending on the selected
tool and arguments, it can generate substantial traffic, modify target state,
or trigger defensive controls.

You are responsible for:

- obtaining explicit authorization;
- keeping every target within the agreed scope;
- understanding the behavior and impact of the selected executable;
- protecting engagement data and credentials;
- complying with applicable law and the target's rules of engagement.

## License

Drost Community Edition is licensed under the
[Apache License 2.0](LICENSE).

Copyright 2026 Drost.

---

**Find out how far an attacker can actually go.**
