# drost-ai

`drost-ai` is a single-container offensive-security toolkit exposed directly to MCP clients over
stdio. Tess starts the MCP process inside the persistent container with `docker exec`; there is no
HTTP service and the container publishes no ports.

## Runtime shape

```text
Tess -> docker exec -i drost-ai drost-mcp -> Drost tool -> container executable
```

The MCP server uses Drost-owned tool names and schemas. Executable-backed tools accept explicit
`arguments: string[]`, an optional workspace-relative working directory, and optional stdin.
Commands use `shell=False`. The server does not impose execution timeouts or truncate output; the
MCP client owns request deadlines and context handling.

The initial catalog exposes 105 executable-backed tools and 23 Drost-native/workspace tools. A
checked coverage ledger accounts for all 124 unique functional names in the reference inventory,
using native Drost implementations or one clear equivalent where the reference listed an alias,
GUI application, library, or external service as though it were a standalone command.

## Build and run

```sh
docker build -t drost-ai:local .
docker run -d --name drost-ai --restart unless-stopped -v drost-ai-workspace:/workspace drost-ai:local
docker exec drost-ai drost-mcp --self-test
```

The multi-architecture Dockerfile targets `linux/amd64` and `linux/arm64`. Registry publication is
deliberately deferred.

Validate the non-native build without publishing it:

```sh
docker buildx build --platform linux/amd64 --progress=plain -t drost-ai:amd64 --load .
```

When a registry is selected later, publish one multi-architecture manifest with:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t REGISTRY/drost-ai:VERSION --push .
```

## Tess registration

From the project where Tess should store the local MCP registration:

```sh
tess mcp add --scope local drost-ai docker -- exec -i -e DROST_MCP_MODE=compact drost-ai drost-mcp
```

Restart Tess after registration, then ask it to call `drost_catalog` and an authorized tool.

Compact mode is intended for model clients with limits on the number of attached tool schemas. It
still exposes the complete catalog through `drost_catalog` and executes any catalog entry through
`drost_execute`. Omit `DROST_MCP_MODE=compact` to expose every executable as an individual MCP tool.
