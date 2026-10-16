import {brandAssets} from './branding.ts';
import {bootstrapCSS} from './generated/ui.ts';
export const BOOTSTRAP_PATH='/assets/bootstrap-5.3.8.min.css';
export function uiAsset(req:Request):Response|null {
 const path=new URL(req.url).pathname;
 const brand=brandAssets[path==='/favicon.ico'?'/assets/portal-icon-v1.ico':path];
 if(path!==BOOTSTRAP_PATH&&!brand)return null;
 if(!['GET','HEAD'].includes(req.method))return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
 const body=brand?(brand.base64?Uint8Array.from(atob(brand.base64),c=>c.charCodeAt(0)):brand.text):bootstrapCSS;
 return new Response(req.method==='HEAD'?null:body,{headers:{'content-type':brand?.contentType||'text/css; charset=utf-8','cache-control':path==='/favicon.ico'?'public, max-age=3600':'public, max-age=31536000, immutable','x-content-type-options':'nosniff'}});
}
