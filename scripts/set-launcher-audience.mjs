import { spawnSync } from 'node:child_process';
const aud=process.env.LAUNCHER_ACCESS_AUD;
if(!aud||! /^[a-f0-9]{64}$/i.test(aud))throw Error('A valid launcher Access audience is required');
if(!process.env.CLOUDFLARE_API_TOKEN||!process.env.CLOUDFLARE_ACCOUNT_ID)throw Error('Worker deployment credentials required');
const result=spawnSync(process.execPath,['node_modules/wrangler/bin/wrangler.js','secret','put','LAUNCHER_ACCESS_AUD','--config','wrangler.deploy.json','--env',''],{input:aud,stdio:['pipe','inherit','inherit'],env:process.env});
if(result.error)throw result.error;
process.exitCode=result.status??1;
