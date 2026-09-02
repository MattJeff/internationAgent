// Le seul endroit du paquet qui parle au demon. Tout le reste construit des
// arguments ; rien d'autre n'ouvre de socket, et le test `forbidden.test.js`
// compte les occurrences de `http.request` pour que cette phrase reste vraie.
import http from 'node:http';

/**
 * La version d'API visee.
 *
 * Pourquoi 1.43 et pas la derniere (1.55, Docker Engine 29.6/29.7, relevee le
 * 2026-09-02 sur docs.docker.com/reference/api/engine) : un chemin prefixe par
 * une version que le demon ne connait pas est refuse, alors qu'une version plus
 * ancienne que la sienne est servie — Docker 29.7 accepte encore 1.40. Viser le
 * plancher commun plutot que le plafond, c'est ce qui fait qu'un client dont le
 * serveur est reste en 24.0 n'a rien a configurer. 1.43 = Docker Engine 24.0.
 *
 * Source du contrat de chaque chemin : la specification OpenAPI que Docker sert
 * lui-meme, https://docs.docker.com/reference/api/engine/version/v1.43.yaml,
 * telechargee et lue le 2026-09-02. Les parametres de requete cites plus bas en
 * sortent, pas d'un billet de blog.
 */
export const API_VERSION = 'v1.43';

/**
 * Le chemin par defaut de la socket du demon.
 *
 * Cite : `docs.docker.com/reference/cli/dockerd/` documente
 * `unix:///var/run/docker.sock` comme la socket par defaut du demon (lu le
 * 2026-09-02). Sur cette machine c'est un lien symbolique vers la socket de
 * Docker Desktop, ce qui ne change rien : on ouvre le chemin, pas sa cible.
 */
export const DEFAULT_SOCKET = '/var/run/docker.sock';

/**
 * Les chemins que ce paquet sait former, et il n'y en a pas d'autres.
 *
 * C'est la moitie « liste » de la decision prise dans `crates/app/src/catalog.rs`
 * au-dessus de `CATALOG` : un `exec` ou un `create` sur une image que le client
 * nomme est l'interpreteur que `crates/app/src/mcp.rs` passe quatre-vingt-dix
 * lignes a refuser sous le nom de SSH. Une liste litterale de gabarits est ce
 * qui rend ce refus verifiable plutot que promis : il n'y a pas de branche a
 * oublier, il y a un tableau a lire.
 *
 * L'identifiant est contraint a de l'hexadecimal ici *aussi*, et pas seulement
 * dans le schema d'entree de l'outil : la traversee de chemin (`../exec`) et
 * l'injection de query (`?x=1&`) meurent sur cette expression avant d'avoir
 * atteint la couche HTTP, meme si un futur outil oublie de valider.
 */
const ALLOWED_PATHS: readonly RegExp[] = [
  /^\/containers\/json$/,
  /^\/containers\/[0-9a-f]{12,64}\/(json|logs|stats|start|stop|restart)$/,
  /^\/images\/json$/,
  /^\/events$/
];

/** Les deux seules methodes. Rien ici ne supprime, donc rien ici ne l'ecrit. */
export type Method = 'GET' | 'POST';

/** Ce qu'on refuse de lire, quoi que reponde le demon. */
const HARD_BYTE_CEILING = 1024 * 1024;

export class DockerError extends Error {}

/**
 * Ou est la socket, et pourquoi les autres formes de `DOCKER_HOST` sont un refus
 * et non une lacune.
 *
 * `DOCKER_HOST` accepte aussi `tcp://`, `ssh://` et `npipe://`. On n'en prend
 * aucune, et `ssh://` est la raison qui porte les trois : c'est litteralement le
 * « droit d'executer ce que le porteur decide » que le catalogue refuse de
 * transformer en connecteur. `tcp://` est plus subtil et refuse quand meme —
 * une socket TCP sans mTLS est un demon root ouvert sur un reseau, et decider
 * de la confiance a lui accorder n'est pas la question a laquelle ce paquet
 * repond.
 */
export function socketPath(env: NodeJS.ProcessEnv = process.env): string {
  const host = env.DOCKER_HOST?.trim();
  if (!host) return DEFAULT_SOCKET;
  if (host.startsWith('unix://')) {
    const path = host.slice('unix://'.length);
    // `unix:///var/run/docker.sock` (trois barres) est la forme canonique ; la
    // forme a deux barres traine dans assez de documentation pour valoir deux
    // lignes plutot qu'un ticket.
    return path.startsWith('/') ? path : `/${path}`;
  }
  if (host.startsWith('/')) return host;
  throw new DockerError(
    `DOCKER_HOST=${host} n'est pas une socket unix. Ce serveur ne parle qu'a une socket unix locale ` +
      `(unix:///var/run/docker.sock ou un chemin absolu) : tcp:// et ssh:// sont des refus, pas des oublis.`
  );
}

function assertAllowed(path: string): void {
  if (!ALLOWED_PATHS.some((allowed) => allowed.test(path))) {
    throw new DockerError(
      `chemin refuse: ${path}. Ce serveur ne forme que la moitie de l'API du moteur qui est une liste.`
    );
  }
}

export interface AskOptions {
  /** Octets lus au maximum avant qu'on coupe la connexion. */
  limit?: number;
  timeoutMs?: number;
  query?: Record<string, string | number | boolean | undefined>;
}

export interface Answer {
  status: number;
  body: Buffer;
  contentType: string;
  /** Vrai si on a coupe le demon en cours de phrase. */
  clipped: boolean;
}

/**
 * Une requete, et une seule facon d'en faire une.
 *
 * La query est construite par `URLSearchParams` et jamais concatenee : c'est ce
 * qui fait qu'une valeur d'argument ne peut pas repartir en morceau de chemin.
 */
export async function ask(method: Method, path: string, options: AskOptions = {}): Promise<Answer> {
  assertAllowed(path);
  const limit = Math.min(options.limit ?? 256 * 1024, HARD_BYTE_CEILING);
  const timeoutMs = options.timeoutMs ?? 15_000;

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined) params.set(key, String(value));
  }
  const query = params.toString();
  const target = `/${API_VERSION}${path}${query ? `?${query}` : ''}`;

  return await new Promise<Answer>((resolve, reject) => {
    const request = http.request(
      { socketPath: socketPath(), path: target, method, headers: { Host: 'docker', Accept: 'application/json' } },
      (response) => {
        const chunks: Buffer[] = [];
        let seen = 0;
        let clipped = false;
        response.on('data', (chunk: Buffer) => {
          seen += chunk.length;
          if (seen > limit) {
            // On coupe la source, on ne se contente pas de jeter ce qu'on a
            // lu : un conteneur bavard doit couter une connexion fermee, pas
            // un tour rempli.
            chunks.push(chunk.subarray(0, Math.max(0, chunk.length - (seen - limit))));
            clipped = true;
            response.destroy();
            return;
          }
          chunks.push(chunk);
        });
        response.on('close', () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks),
            contentType: String(response.headers['content-type'] ?? ''),
            clipped
          })
        );
        response.on('error', reject);
      }
    );
    request.setTimeout(timeoutMs, () => request.destroy(new DockerError(`le demon n'a pas repondu en ${timeoutMs} ms`)));
    request.on('error', (cause) =>
      reject(
        cause instanceof DockerError
          ? cause
          : new DockerError(`socket ${socketPath()} injoignable: ${cause.message}`)
      )
    );
    request.end();
  });
}

/** Le corps, en JSON, avec le message d'erreur du demon quand il y en a un. */
export async function askJson(method: Method, path: string, options: AskOptions = {}): Promise<unknown> {
  const answer = await ask(method, path, options);
  const text = answer.body.toString('utf8');
  if (answer.status >= 400) throw new DockerError(dockerMessage(answer.status, text));
  if (answer.clipped) {
    throw new DockerError(
      `la reponse du demon depasse la limite de ce serveur. Restreignez la demande (filters, limit) plutot que de l'elargir.`
    );
  }
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new DockerError(`le demon a repondu ${answer.status} avec quelque chose qui n'est pas du JSON`);
  }
}

function dockerMessage(status: number, text: string): string {
  try {
    const parsed = JSON.parse(text) as { message?: unknown };
    if (typeof parsed.message === 'string') return `le demon a repondu ${status}: ${parsed.message}`;
  } catch {
    /* le demon ne rend pas toujours du JSON sur erreur */
  }
  return `le demon a repondu ${status}`;
}

/**
 * Le desentrelacement des journaux.
 *
 * La specification decrit un cadrage de huit octets (`STREAM_TYPE`, trois zeros,
 * puis la taille en uint32 big endian) quand le conteneur n'a pas de TTY, et un
 * flux brut quand il en a un — et elle se contredit sur le moyen de distinguer
 * les deux : elle annonce deux `Content-Type` possibles et ecrit dans la meme
 * page que l'endpoint « does not set Content-Type ». On ne fait donc pas
 * confiance a l'en-tete : on tente de lire le buffer comme une suite de cadres
 * et on ne retient ce resultat que s'il tombe *exactement* sur la fin. Un flux
 * brut ne tombe pas juste, sauf a etre vide.
 */
export function demultiplex(body: Buffer): string {
  const parts: Buffer[] = [];
  let at = 0;
  while (at + 8 <= body.length) {
    const kind = body[at];
    if (kind === undefined || kind > 2 || body[at + 1] !== 0 || body[at + 2] !== 0 || body[at + 3] !== 0) {
      return body.toString('utf8');
    }
    const size = body.readUInt32BE(at + 4);
    const from = at + 8;
    if (from + size > body.length) {
      // Dernier cadre tronque par notre propre limite d'octets : on garde ce
      // qui est arrive et on s'arrete, plutot que de declarer le flux brut.
      parts.push(body.subarray(from));
      return parts.length > 1 ? Buffer.concat(parts).toString('utf8') : body.toString('utf8');
    }
    parts.push(body.subarray(from, from + size));
    at = from + size;
  }
  if (at !== body.length) return body.toString('utf8');
  return Buffer.concat(parts).toString('utf8');
}
