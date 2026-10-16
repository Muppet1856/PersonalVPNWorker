import {bootstrapCSS} from './generated/ui.ts';
export const BOOTSTRAP_PATH='/assets/bootstrap-5.3.8.min.css';
export function uiAsset(req:Request):Response|null {
 if(new URL(req.url).pathname!==BOOTSTRAP_PATH)return null;
 if(!['GET','HEAD'].includes(req.method))return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
 return new Response(req.method==='HEAD'?null:bootstrapCSS,{headers:{'content-type':'text/css; charset=utf-8','cache-control':'public, max-age=31536000, immutable','x-content-type-options':'nosniff'}});
}
