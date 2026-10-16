import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const icons={chat:'chat-dots',git:'git',home:'house-door',media:'play-btn',server:'hdd-stack',files:'folder2-open',shield:'shield-check',key:'key',grid:'grid'};
const selected=Object.fromEntries(Object.entries(icons).map(([name,file])=>[name,read(`node_modules/bootstrap-icons/icons/${file}.svg`).trim().replace('<svg ','<svg aria-hidden="true" ')]));
const css=read('node_modules/bootstrap/dist/css/bootstrap.min.css').replace(/\/\*# sourceMappingURL=.*?\*\//g,'');
mkdirSync(new URL('../src/generated/',import.meta.url),{recursive:true});
writeFileSync(new URL('../src/generated/ui.ts',import.meta.url),'// Generated from pinned Bootstrap and Bootstrap Icons packages. See THIRD_PARTY_NOTICES.md.\nexport const bootstrapCSS='+JSON.stringify(css)+';\nexport const APP_ICONS='+JSON.stringify(selected)+';\n');
console.log('Bundled Bootstrap CSS and selected Bootstrap Icons locally.');
