import { createHash, generateKeyPairSync, sign } from 'node:crypto';
const hash = x => createHash('sha256').update(x).digest();
const b64 = x => Buffer.from(x).toString('base64url');
// Minimal CBOR encoder to construct an authenticator's standards-based none attestation.
function cbor(value) {
  const head=(major,n)=>n<24?Buffer.from([(major<<5)|n]):n<256?Buffer.from([(major<<5)|24,n]):Buffer.from([(major<<5)|25,n>>8,n&255]);
  if(Number.isInteger(value)) return value>=0?head(0,value):head(1,-1-value);
  if(Buffer.isBuffer(value)) return Buffer.concat([head(2,value.length),value]);
  if(typeof value==='string') {const x=Buffer.from(value);return Buffer.concat([head(3,x.length),x]);}
  if(value instanceof Map) return Buffer.concat([head(5,value.size),...[...value].flatMap(([k,v])=>[cbor(k),cbor(v)])]);
  throw Error('Unsupported CBOR fixture');
}
export function authenticator(origin = 'http://localhost:8787') {
  const {privateKey, publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const jwk=publicKey.export({format:'jwk'});const id=Buffer.from(crypto.randomUUID());
  const cose=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
  const client=(challenge,type)=>Buffer.from(JSON.stringify({type,challenge,origin,crossOrigin:false}));
  const header=(flags,count)=>{const n=Buffer.alloc(4);n.writeUInt32BE(count);return Buffer.concat([hash('localhost'),Buffer.from([flags]),n]);};
  return { id:b64(id), register(challenge) {
    const clientDataJSON=client(challenge,'webauthn.create');const len=Buffer.alloc(2);len.writeUInt16BE(id.length);
    const authData=Buffer.concat([header(0x45,0),Buffer.alloc(16),len,id,cose]);
    return {id:b64(id),rawId:b64(id),type:'public-key',clientExtensionResults:{},response:{clientDataJSON:b64(clientDataJSON),attestationObject:b64(cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',authData]]))),transports:['internal']}};
  }, login(challenge,count=1) {
    const cd=client(challenge,'webauthn.get');const ad=header(0x05,count);
    return {id:b64(id),rawId:b64(id),type:'public-key',clientExtensionResults:{},response:{clientDataJSON:b64(cd),authenticatorData:b64(ad),signature:b64(sign('sha256',Buffer.concat([ad,hash(cd)]),privateKey))}};
  }};
}
