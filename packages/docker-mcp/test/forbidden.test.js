// Le test le plus important du paquet.
//
// La promesse de ce serveur est negative : « aucun chemin de ce code ne peut
// emettre un exec, un create, un run, un montage hote, un --privileged, un
// commit, un push, ni une suppression de volume ou d'image ». Une promesse
// negative ne se prouve pas en appelant les outils — on ne peut pas appeler
// ceux qui n'existent pas. Elle se prouve en lisant le code et la table.
//
// Trois lectures, qui echouent pour trois raisons differentes :
//
//   1. la table d'outils, nom par nom : ajouter un outil casse le test ;
//   2. les chemins que la table sait former, eprouves avec des arguments
//      hostiles : un gabarit qui laisse passer `../exec` casse le test ;
//   3. le source lui-meme, commentaires retires : ecrire le mot casse le test.
//
// Et une quatrieme, qui est la seule raison pour laquelle on peut croire aux
// trois autres : `les_interdits_attrapent_ce_qu_ils_pretendent_attraper`
// verifie que chaque expression interdite reconnait bien un extrait hostile.
// Un test qui ne peut pas echouer est pire que pas de test.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { TOOL_NAMES, TOOLS } from '../dist/tools.js';
import { ask } from '../dist/docker.js';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));

/** Un fichier, commentaires retires — les commentaires ont le droit de nommer ce qu'ils refusent. */
function code(name) {
  return readFileSync(SRC + name, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function sources() {
  return readdirSync(SRC).filter((name) => name.endsWith('.ts'));
}

/**
 * Les interdits, et pour chacun un extrait qui doit le declencher.
 *
 * L'extrait n'est pas de la decoration : c'est ce qui distingue une expression
 * qui garde du code d'une expression qui ne reconnait rien.
 */
const FORBIDDEN = [
  { why: 'exec sous toutes ses formes', pattern: /exec/i, hostile: '`/containers/${id}/exec`' },
  { why: 'create', pattern: /\bcreate\b/i, hostile: "ask('POST', '/containers/create')" },
  // `/var/run/docker.sock` est le seul « run » legitime du paquet, et il est
  // dans un chemin de socket cite. Le negatif derriere lui est ce qui evite
  // d'avoir a exempter le fichier entier.
  { why: 'run', pattern: /(?<!\/var\/)\brun\b/i, hostile: 'function run(image) {}' },
  { why: 'commit', pattern: /\bcommit\b/i, hostile: "ask('POST', '/commit')" },
  { why: 'push vers un registre', pattern: /\/push|['"`]push['"`]/, hostile: '`/images/${name}/push`' },
  { why: 'pull depuis un registre', pattern: /\/images\/create|['"`]pull['"`]/, hostile: "'/images/create?fromImage=alpine'" },
  { why: 'construction d’image', pattern: /\/build\b/, hostile: "ask('POST', '/build')" },
  { why: 'montage hote', pattern: /hostconfig|\bbinds\b|\bmounts\b/i, hostile: 'HostConfig: { Binds: ["/:/host"] }' },
  { why: '--privileged', pattern: /privileged/i, hostile: 'Privileged: true' },
  { why: 'network: host', pattern: /networkmode/i, hostile: 'NetworkMode: "host"' },
  { why: 'volumes', pattern: /\/volumes|\bvolume\b/i, hostile: "ask('DELETE', '/volumes/data')" },
  { why: 'suppression', pattern: /['"`](DELETE|PUT|PATCH)['"`]|\bprune\b/i, hostile: "ask('DELETE', '/images/x')" },
  { why: 'signal arbitraire (kill)', pattern: /\bkill\b/i, hostile: '`/containers/${id}/kill`' },
  { why: 'attach / connexion detournee', pattern: /\battach\b|\bhijack/i, hostile: '`/containers/${id}/attach`' }
];

test('les interdits attrapent ce qu’ils pretendent attraper', () => {
  // Sans ceci, une expression mal ecrite rendrait le test suivant toujours vert.
  for (const { why, pattern, hostile } of FORBIDDEN) {
    assert.ok(pattern.test(hostile), `l'interdit « ${why} » ne reconnait pas ${hostile}`);
  }
});

test('aucun verbe interdit n’apparait dans le code', () => {
  const source = sources().map(code).join('\n');
  assert.ok(source.length > 2000, 'le source n’a pas ete lu — un test qui lit du vide ne prouve rien');
  for (const { why, pattern } of FORBIDDEN) {
    const hit = source.match(pattern);
    assert.equal(hit, null, `« ${why} » apparait dans le code: ${hit && hit[0]}`);
  }
});

test('une seule fonction ouvre une connexion, et elle est dans docker.ts', () => {
  assert.equal(code('docker.ts').match(/http\.request/g)?.length, 1);
  for (const name of sources().filter((n) => n !== 'docker.ts')) {
    const other = code(name);
    assert.ok(!/http\.request|node:net|node:child_process|\bfetch\(/.test(other), `${name} ouvre sa propre connexion`);
  }
});

test('la table expose exactement les neuf outils convenus', () => {
  assert.deepEqual(TOOL_NAMES, [
    'container_inspect',
    'container_logs',
    'container_restart',
    'container_start',
    'container_stats',
    'container_stop',
    'containers_list',
    'events_recent',
    'images_list'
  ]);
});

test('aucun outil n’utilise une methode autre que GET ou POST', () => {
  for (const tool of TOOLS) assert.ok(tool.method === 'GET' || tool.method === 'POST', tool.name);
});

// Le gabarit de chemin de chaque outil, nourri de tout ce qu'on peut esperer y
// glisser. Ce que la couche HTTP accepte est une liste litterale d'expressions ;
// ce test verifie qu'aucun gabarit ne sort de cette liste, meme avec ca dedans.
const HOSTILE_IDS = [
  '../../exec',
  'abc123abc123/exec',
  'abc123abc123?x=1',
  'abc123abc123/../../images/create',
  '%2e%2e%2fexec',
  'alpine sh -c id',
  '',
  'ABC123ABC123',
  'a'.repeat(200)
];

const PATH_SHAPE = /^\/(containers\/json|containers\/[0-9a-f]{12,64}\/(json|logs|stats|start|stop|restart)|images\/json|events)$/;

test('aucun gabarit ne produit un chemin acceptable, sauf avec un id hexadecimal', async () => {
  const legitimate = '0123456789ab';
  for (const tool of TOOLS) {
    const sane = tool.path({ id: legitimate });
    assert.match(sane, PATH_SHAPE, `${tool.name} avec un id legitime`);
    for (const id of HOSTILE_IDS) {
      const built = tool.path({ id });
      if (built === sane) continue; // chemin constant : l'outil ne lit pas d'id du tout
      await assert.rejects(
        () => ask(tool.method, built),
        (error) => /chemin refuse/.test(error.message),
        `${tool.name} a forme ${built} et la couche HTTP l'a laisse passer`
      );
    }
  }
});

test('la couche HTTP refuse tout chemin hors liste, avant d’ouvrir la socket', async () => {
  const refused = [
    '/containers/0123456789ab/exec',
    '/containers/create',
    '/images/create',
    '/build',
    '/volumes/data',
    '/containers/0123456789ab',
    '/containers/0123456789ab/kill',
    '/containers/0123456789ab/../create',
    '/containers/ABC123ABC123/json',
    '/containers/0123456789ab/json?follow=1',
    '/exec/x/start',
    '/containers/json/../../build'
  ];
  for (const path of refused) {
    await assert.rejects(
      () => ask('POST', path),
      (error) => /chemin refuse/.test(error.message),
      `${path} aurait du etre refuse`
    );
  }
});

test('un id qui n’est pas hexadecimal est refuse par le schema d’entree', async () => {
  const logs = TOOLS.find((tool) => tool.name === 'container_logs');
  for (const id of HOSTILE_IDS) {
    await assert.rejects(() => logs.call({ id }), `${id} aurait du etre refuse`);
  }
});
