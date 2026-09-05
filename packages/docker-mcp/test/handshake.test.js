// Le paquet parle-t-il vraiment MCP ? Les autres tests lisent le code ; celui-ci
// lance le binaire et lui parle, avec le client du SDK officiel, pour que la
// liste d'outils qu'un client verra soit celle qu'on croit avoir ecrite. Il ne
// touche pas au demon Docker : `tools/list` ne fait aucune requete.

import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const ENTRY = fileURLToPath(new URL('../dist/index.js', import.meta.url));

test('un client MCP voit exactement les neuf outils, et pas un de plus', async () => {
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [ENTRY] }));
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(
      tools.map((tool) => tool.name).sort(),
      [
        'container_inspect',
        'container_logs',
        'container_restart',
        'container_start',
        'container_stats',
        'container_stop',
        'containers_list',
        'events_recent',
        'images_list'
      ]
    );
    // Les bornes de `container_logs` doivent etre visibles dans le schema : un
    // plafond qui n'est que dans le code se contourne en le demandant poliment.
    const logs = tools.find((tool) => tool.name === 'container_logs');
    assert.equal(logs.inputSchema.properties.tail.maximum, 2000);
    assert.equal(logs.inputSchema.properties.max_bytes.maximum, 262144);
    assert.deepEqual(logs.inputSchema.required, ['id']);
  } finally {
    await client.close();
  }
});
