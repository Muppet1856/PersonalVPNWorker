import auth, { type AuthEnv } from './auth.ts';
import { SqlStore } from './store.ts';

type Env = Omit<AuthEnv, 'DB'> & { FAMILY_AUTH: DurableObjectNamespace };

// One stable identity owns this family's accounts, credentials and sessions.
// Changing the object name would select a different, empty database.
const FAMILY_OBJECT_NAME = 'zellen-family-v1';
export class FamilyAuth {
  private authEnv: AuthEnv;
  constructor(ctx: DurableObjectState, env: Env) {
    this.authEnv = { ...env, DB: new SqlStore(ctx.storage) };
  }
  fetch(request: Request) { return auth.fetch(request, this.authEnv); }
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const id = env.FAMILY_AUTH.idFromName(FAMILY_OBJECT_NAME);
    return env.FAMILY_AUTH.get(id).fetch(request);
  },
} satisfies ExportedHandler<Env>;
