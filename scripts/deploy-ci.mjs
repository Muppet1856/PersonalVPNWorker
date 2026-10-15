import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const dryRun=process.argv.includes('--dry-run');
if(!dryRun) {
  for(const key of ['CLOUDFLARE_API_TOKEN','CLOUDFLARE_ACCOUNT_ID']) {
    if(!process.env[key]) {console.error(`Add ${key} under GitHub Settings > Secrets and variables > Actions > Secrets`);process.exit(1);}
  }
}
const directory=mkdtempSync(join(tmpdir(),'worker-deploy-'));
try {
  const args=['node_modules/wrangler/bin/wrangler.js','deploy','--config','wrangler.deploy.json','--env',''];
  if(process.env.ADMIN_SETUP_SECRET) {
    const secretFile=join(directory,'secrets.json');
    writeFileSync(secretFile,JSON.stringify({ADMIN_SETUP_SECRET:process.env.ADMIN_SETUP_SECRET}),{mode:0o600});
    args.push('--secrets-file',secretFile);
  }
  if(dryRun)args.push('--dry-run','--outdir','dist/deploy-ci-check');
  // Resolve the repository-pinned Wrangler CLI. Secret values never enter argv.
  args[0]=resolve(args[0]);
  const result=spawnSync(process.execPath,args,{stdio:'inherit',env:process.env});
  if(result.error)throw result.error;
  process.exitCode=result.status ?? 1;
} finally {rmSync(directory,{recursive:true,force:true});}
