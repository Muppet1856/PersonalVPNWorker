const origin=process.env.PUBLIC_ORIGIN;
if(!origin)throw Error('PUBLIC_ORIGIN is required');
let failure;
for(let attempt=0;attempt<6;attempt++) {
 try {
  const options={redirect:'error',signal:AbortSignal.timeout(15000)};
  const discovery=await fetch(origin+'/.well-known/openid-configuration',options);
  if(!discovery.ok)throw Error('Discovery endpoint did not return success');const config=await discovery.json();
  if(config.issuer!==origin||config.jwks_uri!==origin+'/oidc/jwks')throw Error('Unexpected OIDC issuer or key endpoint');
  const response=await fetch(config.jwks_uri,{...options,signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw Error('Public key endpoint did not return success');const jwks=await response.json();
  if(!jwks.keys?.length||jwks.keys.some(key=>key.kty!=='RSA'||key.d||!key.kid))throw Error('Invalid public signing-key response');
  console.log('Deployed OIDC discovery and public signing-key endpoints are reachable.');process.exit(0);
 }catch(error){failure=error;await new Promise(resolve=>setTimeout(resolve,3000));}
}
console.error(failure?.message||'OIDC verification failed');process.exitCode=1;
