// main.ts — the handshake between this entry and the trial harness.
//
// This file holds no forge logic at all: the forge itself lives in app.ts.
// All this file does is bring the forge's server up, point the harness at it,
// and stay out of the way until the harness says the trial is over:
//
//   - The harness's address comes from MAKEFUN_ENV_URL. With no address there
//     is nobody to talk to, so the process gives up immediately.
//   - The server binds port 0, which asks the kernel to hand it any free port.
//     Port 8080 is the harness's own and must never be taken.
//   - The bound port is announced with one POST to /register. The harness
//     remembers where the request came from, adds the port, and from then on
//     treats that address as the forge.
//   - While the suite runs, this process polls GET /done. Each answer arrives
//     at once — false while the suite is still working, true once its export
//     is written — so polling is a short repeated question, never a held-open
//     request. The process only leaves once the answer is true.
//   - Then the server is closed and the process exits 0. A crash, an early
//     exit, or a register that never lands all leave the trial with no forge,
//     so every step here is retried patiently instead of failing fast.

import { createApp } from './app.ts';

// Where the harness listens, without a trailing slash. Empty means "no harness".
const harnessUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (harnessUrl === '') {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
  process.exit(1);
}

// One request is given this long before it is abandoned and retried.
const REQUEST_TIMEOUT_MS = 30_000;
// Retries wait this long after the first failure, doubling each time, and
// never longer than the cap below.
const FIRST_BACKOFF_MS = 250;
const MAX_BACKOFF_MS = 2_000;

/** Resolve after `ms` milliseconds. */
function pause(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** How long to wait before the next try after `failures` failed tries. */
function backoffFor(failures: number): number {
  const grown = FIRST_BACKOFF_MS * 2 ** Math.min(failures, 8);
  return grown < MAX_BACKOFF_MS ? grown : MAX_BACKOFF_MS;
}

/**
 * Tell the harness which port the forge bound. A 200 means the announcement
 * landed; a 409 means some earlier announcement already won, which is fine
 * too — this process simply waits like any other. A 400 or 405 means the
 * announcement itself was wrong, so there is no point retrying and the
 * process fails. Any other answer, or a request that never gets through
 * (the harness may still be starting), is retried after a backoff.
 */
async function announcePort(port: number): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const response = await fetch(`${harnessUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.status === 200 || response.status === 409) {
        return;
      }
      if (response.status === 400 || response.status === 405) {
        const detail = await response.text();
        throw new Error(`register answered HTTP ${response.status}: ${detail}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('register answered HTTP ')) {
        throw error;
      }
      // Anything else is a transient failure: fall through to the retry below.
    }
    await pause(backoffFor(failures));
  }
}

/**
 * Keep asking the harness whether the trial is finished. The answer is a
 * plain JSON body; only {"done": true} ends the wait. A failed request, a
 * timeout, or an answer that is not finished yet all mean the same thing:
 * wait a little and ask again.
 */
async function awaitFinish(): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const response = await fetch(`${harnessUrl}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) {
        const payload = (await response.json()) as { done?: unknown };
        if (payload.done === true) {
          return;
        }
      }
    } catch {
      // The harness is not answering yet: keep polling.
    }
    await pause(backoffFor(failures));
  }
}

/**
 * The whole life of the process: bind the forge, announce the port, then
 * wait for the harness to say the trial is done.
 */
async function run(): Promise<void> {
  const server = createApp();
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => {
      const bound = server.address();
      if (bound === null || typeof bound === 'string') {
        reject(new Error('the server did not bind an ephemeral TCP port'));
        return;
      }
      resolve(bound.port);
    });
  });
  process.stdout.write(`[entry] listening on port ${port}\n`);

  await announcePort(port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await awaitFinish();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await run();
  process.exit(0);
} catch (error) {
  const reason = error instanceof Error ? error.message : String(error);
  process.stderr.write(`[entry] ${reason}\n`);
  process.exit(1);
}
