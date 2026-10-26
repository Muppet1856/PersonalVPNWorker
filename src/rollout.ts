import {configuredApps} from './permissions.ts';
// Reviewed rollout data, not a generic allow-all switch. Only these previously
// unrestricted applications may be preserved for pre-existing active members.
const approvedLegacyHosts=new Set(['chat.zellen.ai','git.zellen.io']);
export function legacyRolloutGrants(env:{APP_LINKS_JSON?:string}):string[] {
 return configuredApps(env).map(app=>app.id).filter(id=>approvedLegacyHosts.has(id));
}
