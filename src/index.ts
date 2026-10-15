import auth, { type AuthEnv } from './auth.ts';
import { SqlStore } from './store.ts';
import { handleLauncher } from './launcher.ts';

type Env = Omit<AuthEnv, 'DB'> & { FAMILY_AUTH: DurableObjectNamespace };

// One stable identity owns this family's accounts, credentials and sessions.
// Changing the object name would select a different, empty database.
export class FamilyAuth {
  private authEnv: AuthEnv;
  constructor(ctx: DurableObjectState, env: Env) {
    this.authEnv = { ...env, DB: new SqlStore(ctx.storage) };
  }
  fetch(request: Request) { return auth.fetch(request, this.authEnv); }
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin=new URL(request.url).origin;
    if(env.LAUNCHER_ORIGIN && origin===env.LAUNCHER_ORIGIN)return handleLauncher(request,env);
    const id = env.FAMILY_AUTH.idFromName(env.FAMILY_ID || 'family-v1');
    return env.FAMILY_AUTH.get(id).fetch(request);
  },
} satisfies ExportedHandler<Env>;
