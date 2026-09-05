// La table d'outils. C'est elle que lit le test d'interdiction, et c'est pour
// ca qu'elle est une donnee et pas neuf appels a `registerTool` disperses : une
// promesse sur ce qu'un serveur ne peut pas faire se verifie en lisant une
// liste, pas en relisant neuf fermetures.
import { z } from 'zod';

import { ask, askJson, demultiplex, DockerError, type Method } from './docker.js';

/**
 * L'identifiant d'un conteneur, et rien d'autre.
 *
 * On refuse un nom (`nginx`) alors que le demon l'accepterait, et c'est
 * delibere : le catalogue dit « demarrer, arreter, redemarrer **un conteneur qui
 * existe deja, par son id** ». Un identifiant hexadecimal n'a aucune forme qui
 * puisse redevenir un morceau de chemin, alors qu'un nom en a plusieurs. Le
 * cout est nul pour l'appelant : `containers_list` rend l'id complet.
 */
const ContainerId = z
  .string()
  .regex(/^[0-9a-f]{12,64}$/, "un id de conteneur en hexadecimal (12 a 64 caracteres), tel que rendu par containers_list");

/** Ce qu'un tour peut absorber de journaux. Voir `container_logs`. */
const LOG_LINES_DEFAULT = 200;
const LOG_LINES_MAX = 2000;
const LOG_BYTES_DEFAULT = 64 * 1024;
const LOG_BYTES_MAX = 256 * 1024;

export interface Tool {
  name: string;
  title: string;
  description: string;
  input: z.ZodRawShape;
  /** Lecture seule au sens de MCP : cet outil ne change rien sur le demon. */
  readOnly: boolean;
  /** Le gabarit de chemin, expose pour que le test puisse l'eprouver. */
  path(args: Record<string, unknown>): string;
  method: Method;
  call(args: Record<string, unknown>): Promise<string>;
}

/** Le seuil au-dela duquel une reponse du demon n'entre pas dans un tour. */
const JSON_LIMIT = 256 * 1024;

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

/**
 * Les trois verbes de cycle de vie, qui different d'une lettre et d'un code de
 * retour. Une fabrique plutot que trois copies parce que la seule chose qui
 * change entre eux est le mot, et qu'une copie est un endroit ou la limite peut
 * diverger sans qu'on le voie.
 */
function lifecycle(verb: 'start' | 'stop' | 'restart', title: string, description: string): Tool {
  return {
    name: `container_${verb}`,
    title,
    description,
    input: {
      id: ContainerId,
      ...(verb === 'start'
        ? {}
        : {
            timeout_seconds: z
              .number()
              .int()
              .min(0)
              .max(300)
              .optional()
              .describe('secondes avant que le demon passe de SIGTERM a SIGKILL')
          })
    },
    readOnly: false,
    method: 'POST',
    path: (args) => `/containers/${String(args.id)}/${verb}`,
    async call(args) {
      const id = ContainerId.parse(args.id);
      const seconds = verb === 'start' ? undefined : (args.timeout_seconds as number | undefined);
      const answer = await ask('POST', `/containers/${id}/${verb}`, {
        query: { t: seconds },
        // Un arret laisse au conteneur le temps qu'on lui a donne, plus la
        // marge du demon ; le defaut de 15 s de `ask` couperait avant lui.
        timeoutMs: (seconds ?? 10) * 1000 + 20_000
      });
      if (answer.status === 204) return `${id} : ${verb} accepte par le demon.`;
      // 304 est documente pour start et stop : « container already started » /
      // « already stopped ». Ce n'est pas une erreur, c'est la reponse.
      if (answer.status === 304) return `${id} : deja dans cet etat, le demon n'a rien fait.`;
      throw new DockerError(`${verb} refuse (${answer.status}): ${answer.body.toString('utf8').slice(0, 500)}`);
    }
  };
}

export const TOOLS: readonly Tool[] = [
  {
    name: 'containers_list',
    title: 'Lister les conteneurs',
    description:
      "Les conteneurs du demon local et leur etat. Par defaut ceux qui tournent ; `all` ajoute les arretes. " +
      "L'`Id` complet rendu ici est ce que les autres outils attendent.",
    input: {
      all: z.boolean().optional().describe('inclure les conteneurs arretes'),
      limit: z.number().int().min(1).max(200).optional().describe('les N plus recents'),
      status: z
        .enum(['created', 'restarting', 'running', 'removing', 'paused', 'exited', 'dead'])
        .optional()
        .describe("filtrer sur l'etat"),
      name: z.string().max(128).optional().describe('filtrer sur une sous-chaine du nom')
    },
    readOnly: true,
    method: 'GET',
    path: () => '/containers/json',
    async call(args) {
      // Le filtre est un JSON `map[string][]string` (spec v1.43). On le
      // construit ici plutot que de laisser l'appelant en fournir un : un
      // filtre libre est une surface de plus a lire, et les deux qu'on offre
      // couvrent ce qu'une equipe demande.
      const filters: Record<string, string[]> = {};
      if (typeof args.status === 'string') filters.status = [args.status];
      if (typeof args.name === 'string' && args.name) filters.name = [args.name];
      return pretty(
        await askJson('GET', '/containers/json', {
          limit: JSON_LIMIT,
          query: {
            all: args.all === true ? 'true' : undefined,
            limit: args.limit as number | undefined,
            filters: Object.keys(filters).length ? JSON.stringify(filters) : undefined
          }
        })
      );
    }
  },
  {
    name: 'container_inspect',
    title: 'Inspecter un conteneur',
    description:
      "La configuration complete d'un conteneur : image, etat, code de sortie, sante, reseau, variables " +
      "d'environnement telles que le demon les a enregistrees.",
    input: { id: ContainerId },
    readOnly: true,
    method: 'GET',
    path: (args) => `/containers/${String(args.id)}/json`,
    async call(args) {
      const id = ContainerId.parse(args.id);
      return pretty(await askJson('GET', `/containers/${id}/json`, { limit: JSON_LIMIT }));
    }
  },
  {
    name: 'container_logs',
    title: 'Lire les journaux d’un conteneur',
    description:
      "Les dernieres lignes de stdout et stderr. Borne en lignes ET en octets, aux deux bouts : le nombre de " +
      "lignes est demande au demon, la taille est coupee a la lecture. Ne suit pas le flux.",
    input: {
      id: ContainerId,
      tail: z
        .number()
        .int()
        .min(1)
        .max(LOG_LINES_MAX)
        .optional()
        .describe(`lignes depuis la fin (defaut ${LOG_LINES_DEFAULT}, maximum ${LOG_LINES_MAX})`),
      max_bytes: z
        .number()
        .int()
        .min(1024)
        .max(LOG_BYTES_MAX)
        .optional()
        .describe(`octets rendus au maximum (defaut ${LOG_BYTES_DEFAULT}, maximum ${LOG_BYTES_MAX})`),
      stdout: z.boolean().optional(),
      stderr: z.boolean().optional(),
      timestamps: z.boolean().optional(),
      since_seconds: z.number().int().min(1).max(30 * 24 * 3600).optional().describe('ne rien rendre de plus vieux')
    },
    readOnly: true,
    method: 'GET',
    path: (args) => `/containers/${String(args.id)}/logs`,
    async call(args) {
      const id = ContainerId.parse(args.id);
      const tail = (args.tail as number | undefined) ?? LOG_LINES_DEFAULT;
      const maxBytes = (args.max_bytes as number | undefined) ?? LOG_BYTES_DEFAULT;
      const stdout = args.stdout !== false;
      const stderr = args.stderr !== false;
      if (!stdout && !stderr) throw new DockerError('stdout et stderr tous les deux a false ne demande rien');

      const answer = await ask('GET', `/containers/${id}/logs`, {
        // Deux fois la borne de sortie : le cadrage de huit octets par ligne et
        // les lignes qu'on va jeter par la fin doivent tenir dans la lecture,
        // sinon on couperait la socket avant d'avoir les dernieres lignes —
        // qui sont justement celles qu'on veut.
        limit: Math.min(maxBytes * 2 + 8 * tail + 4096, 1024 * 1024),
        query: {
          stdout: stdout ? 'true' : undefined,
          stderr: stderr ? 'true' : undefined,
          tail: String(tail),
          timestamps: args.timestamps === true ? 'true' : undefined,
          since: args.since_seconds ? Math.floor(Date.now() / 1000) - (args.since_seconds as number) : undefined
        }
      });
      if (answer.status >= 400) {
        throw new DockerError(`journaux refuses (${answer.status}): ${answer.body.toString('utf8').slice(0, 500)}`);
      }
      let text = demultiplex(answer.body);
      // On garde la FIN : quand un conteneur deborde, ce qui interesse est ce
      // qu'il a dit en dernier, pas ce qu'il disait il y a une heure.
      if (Buffer.byteLength(text, 'utf8') > maxBytes) {
        text = Buffer.from(text, 'utf8').subarray(-maxBytes).toString('utf8');
        text = `[... coupe a ${maxBytes} octets, seule la fin est ci-dessous ...]\n${text}`;
      }
      return text || '(aucune ligne)';
    }
  },
  {
    name: 'container_stats',
    title: 'Statistiques d’un conteneur',
    description:
      "Un releve de CPU, memoire, reseau et E/S bloc. Le releve n'est pas instantane : le demon rend deux " +
      "cycles pour que `precpu_stats` permette de calculer un pourcentage, ce qui coute environ une seconde.",
    input: { id: ContainerId },
    readOnly: true,
    method: 'GET',
    path: (args) => `/containers/${String(args.id)}/stats`,
    async call(args) {
      const id = ContainerId.parse(args.id);
      // `stream=false` et PAS `one-shot=true` : one-shot rend `precpu_stats` a
      // zero, donc un pourcentage CPU incalculable, ce qui est la seule chose
      // qu'on vient chercher. Le prix est la seconde d'attente.
      return pretty(await askJson('GET', `/containers/${id}/stats`, { query: { stream: 'false' }, limit: JSON_LIMIT, timeoutMs: 20_000 }));
    }
  },
  {
    name: 'images_list',
    title: 'Lister les images presentes',
    description: "Les images deja presentes sur cette machine, avec leurs tags et leur taille. Ne va rien chercher au registre.",
    input: {
      all: z.boolean().optional().describe('inclure les couches intermediaires'),
      reference: z.string().max(256).optional().describe('filtrer sur un nom, par exemple `nginx` ou `nginx:1.27`')
    },
    readOnly: true,
    method: 'GET',
    path: () => '/images/json',
    async call(args) {
      const filters: Record<string, string[]> = {};
      if (typeof args.reference === 'string' && args.reference) filters.reference = [args.reference];
      return pretty(
        await askJson('GET', '/images/json', {
          limit: JSON_LIMIT,
          query: {
            all: args.all === true ? 'true' : undefined,
            filters: Object.keys(filters).length ? JSON.stringify(filters) : undefined
          }
        })
      );
    }
  },
  {
    name: 'events_recent',
    title: 'Les evenements recents du demon',
    description:
      "Ce qui s'est passe sur la machine pendant une fenetre passee : demarrages, arrets, morts, changements " +
      "de sante. C'est la reponse a « pourquoi c'est tombe ». Fenetre fermee, jamais un flux ouvert.",
    input: {
      since_seconds: z.number().int().min(1).max(24 * 3600).optional().describe('taille de la fenetre (defaut 3600)'),
      container_id: ContainerId.optional().describe('ne garder que les evenements de ce conteneur'),
      limit: z.number().int().min(1).max(500).optional().describe('evenements rendus au maximum (defaut 100)')
    },
    readOnly: true,
    method: 'GET',
    path: () => '/events',
    async call(args) {
      const window = (args.since_seconds as number | undefined) ?? 3600;
      const limit = (args.limit as number | undefined) ?? 100;
      const now = Math.floor(Date.now() / 1000);
      const filters: Record<string, string[]> = {};
      if (typeof args.container_id === 'string') filters.container = [ContainerId.parse(args.container_id)];

      // `until` est ce qui fait la difference entre une lecture et un flux
      // ouvert : sans lui le demon garde la connexion et attend le prochain
      // evenement, c'est-a-dire pour toujours.
      const answer = await ask('GET', '/events', {
        limit: JSON_LIMIT,
        query: {
          since: String(now - window),
          until: String(now),
          filters: Object.keys(filters).length ? JSON.stringify(filters) : undefined
        }
      });
      if (answer.status >= 400) {
        throw new DockerError(`evenements refuses (${answer.status}): ${answer.body.toString('utf8').slice(0, 500)}`);
      }
      // Le corps est du JSON ligne par ligne, pas un tableau.
      const lines = answer.body.toString('utf8').split('\n').filter((line) => line.trim());
      const kept = lines.slice(-limit).map((line) => {
        try {
          return JSON.parse(line) as unknown;
        } catch {
          return { unparsed: line };
        }
      });
      const note = lines.length > limit ? `(${lines.length - kept.length} evenements plus anciens omis)\n` : '';
      return `${note}${pretty(kept)}`;
    }
  },
  lifecycle(
    'start',
    'Demarrer un conteneur existant',
    "Demarre un conteneur deja defini, par son id. Ne fabrique aucun conteneur et ne choisit aucune image : " +
      "si l'id n'existe pas, le demon repond 404 et rien n'est fait."
  ),
  lifecycle(
    'stop',
    'Arreter un conteneur',
    "SIGTERM puis SIGKILL apres le delai. Le conteneur reste defini et peut etre redemarre."
  ),
  lifecycle('restart', 'Redemarrer un conteneur', "Arret puis demarrage du meme conteneur, par son id.")
];

/** Les noms exposes, tries. Le test d'interdiction commence par cette liste. */
export const TOOL_NAMES: readonly string[] = TOOLS.map((tool) => tool.name).sort();
