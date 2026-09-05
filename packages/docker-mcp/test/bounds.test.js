// Les deux morceaux de logique non triviale du paquet : le desentrelacement du
// flux de journaux, et la resolution de DOCKER_HOST. Les deux se cassent en
// silence — un flux mal lu rend du binaire lisible-a-moitie, un DOCKER_HOST mal
// lu ouvre une socket qui n'est pas celle qu'on croit.

import assert from 'node:assert/strict';
import test from 'node:test';

import { API_VERSION, DEFAULT_SOCKET, demultiplex, socketPath } from '../dist/docker.js';

function frame(kind, text) {
  const payload = Buffer.from(text, 'utf8');
  const header = Buffer.alloc(8);
  header[0] = kind;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

test('un flux entrelace rend le texte des deux voies, dans l’ordre', () => {
  const body = Buffer.concat([frame(1, 'sur stdout\n'), frame(2, 'sur stderr\n'), frame(1, 'et encore\n')]);
  assert.equal(demultiplex(body), 'sur stdout\nsur stderr\net encore\n');
});

test('un flux brut (conteneur avec TTY) passe tel quel', () => {
  // La specification annonce deux Content-Type possibles et ecrit sur la meme
  // page que l'endpoint n'en pose pas ; on ne peut donc pas s'y fier, et c'est
  // le cadrage lui-meme qui doit trancher. Ce texte ne se lit pas comme des
  // cadres : le premier octet vaut 0x6c, au-dela des trois types connus.
  const raw = Buffer.from('le conteneur parle directement, sans cadrage\n', 'utf8');
  assert.equal(demultiplex(raw), raw.toString('utf8'));
});

test('un dernier cadre coupe par notre limite ne fait pas basculer le reste en binaire', () => {
  const complete = frame(1, 'ligne entiere\n');
  const truncated = frame(1, 'ligne coupee au milieu').subarray(0, 8 + 5);
  const out = demultiplex(Buffer.concat([complete, truncated]));
  assert.ok(out.startsWith('ligne entiere\n'), out);
  assert.ok(out.includes('ligne'), out);
});

test('un corps vide rend une chaine vide et pas une exception', () => {
  assert.equal(demultiplex(Buffer.alloc(0)), '');
});

test('DOCKER_HOST: absent, unix://, chemin absolu', () => {
  assert.equal(socketPath({}), DEFAULT_SOCKET);
  assert.equal(socketPath({ DOCKER_HOST: 'unix:///var/run/docker.sock' }), '/var/run/docker.sock');
  assert.equal(socketPath({ DOCKER_HOST: 'unix://var/run/docker.sock' }), '/var/run/docker.sock');
  assert.equal(socketPath({ DOCKER_HOST: '/home/x/.docker/run/docker.sock' }), '/home/x/.docker/run/docker.sock');
});

test('DOCKER_HOST: tcp:// et ssh:// sont des refus, pas des defauts silencieux', () => {
  // ssh:// est litteralement l'objection que `crates/app/src/mcp.rs` argumente
  // sur quatre-vingt-dix lignes ; retomber sur la socket par defaut ferait
  // croire au client qu'il parle a la machine qu'il a nommee.
  for (const host of ['tcp://10.0.0.4:2375', 'ssh://ops@prod', 'npipe:////./pipe/docker_engine', 'http://x']) {
    assert.throws(() => socketPath({ DOCKER_HOST: host }), /socket unix/, host);
  }
});

test('la version d’API est epinglee et prefixe chaque chemin', () => {
  // Un chemin non prefixe est servi par le demon avec sa version a lui, ce qui
  // fait dependre la forme des reponses de la machine du client.
  assert.equal(API_VERSION, 'v1.43');
});
