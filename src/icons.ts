import { APP_ICONS } from './generated/ui.ts';
export { APP_ICONS };
export type AppIcon=keyof typeof APP_ICONS;
export function appIconKey(name:string,url:string,explicit?:string):AppIcon {
 if(explicit&&Object.hasOwn(APP_ICONS,explicit))return explicit as AppIcon;
 let host='';try{host=new URL(url).hostname.split('.')[0];}catch{}
 const value=(name+' '+host).toLowerCase();
 if(/chat|openwebui|assistant|\bai\b/.test(value))return 'chat';
 if(/git|code|source/.test(value))return 'git';
 if(/home|automation/.test(value))return 'home';
 if(/media|plex|jellyfin|video/.test(value))return 'media';
 if(/nas|files|drive|storage/.test(value))return 'files';
 if(/server|dsm|admin|monitor/.test(value))return 'server';
 return 'grid';
}
