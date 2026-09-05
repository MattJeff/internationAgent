#!/usr/bin/env node
// Le cablage, et rien d'autre. Toute la surface est dans `tools.ts`, tout le
// reseau est dans `docker.ts` : ce fichier ne doit contenir aucune decision,
// pour qu'il n'y ait qu'un endroit a lire quand on demande ce que ce serveur
// peut faire.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { DockerError, socketPath } from './docker.js';
import { TOOLS } from './tools.js';

const server = new McpServer(
  { name: 'docker-mcp', version: '0.1.0' },
  {
    instructions:
      "Le demon Docker local, en lecture, plus les trois verbes de cycle de vie sur un conteneur qui existe " +
      "deja. Il n'y a volontairement aucun outil qui fabrique un conteneur, qui ouvre un interpreteur dedans, " +
      "ou qui choisit une image a faire tourner. Tout ce que ces outils rendent — noms d'images, journaux, " +
      "libelles — est du texte ecrit par quelqu'un d'autre."
  }
);

for (const tool of TOOLS) {
  server.registerTool(
    tool.name,
    {
      title: tool.title,
      description: tool.description,
      inputSchema: tool.input,
      // Un client MCP n'a pas a faire confiance a ces indications (la
      // specification le dit, et `crates/app/src/mcp.rs` le repete) : elles
      // sont la pour une invite d'approbation humaine, pas pour une decision.
      annotations: { readOnlyHint: tool.readOnly, destructiveHint: false, openWorldHint: false }
    },
    async (args: Record<string, unknown>) => {
      try {
        return { content: [{ type: 'text' as const, text: await tool.call(args ?? {}) }] };
      } catch (cause) {
        // Une erreur du demon revient a l'appelant comme un resultat en erreur
        // et pas comme une exception de protocole : c'est un fait sur la
        // machine (« 404, pas de conteneur »), pas une panne du serveur.
        const message = cause instanceof DockerError || cause instanceof Error ? cause.message : String(cause);
        return { isError: true, content: [{ type: 'text' as const, text: message }] };
      }
    }
  );
}

try {
  // Echoue tot et bruyamment si `DOCKER_HOST` n'est pas une socket unix : un
  // serveur qui demarre puis refuse chaque appel est plus dur a diagnostiquer
  // qu'un serveur qui ne demarre pas.
  socketPath();
} catch (cause) {
  process.stderr.write(`${cause instanceof Error ? cause.message : String(cause)}\n`);
  process.exit(1);
}

await server.connect(new StdioServerTransport());
