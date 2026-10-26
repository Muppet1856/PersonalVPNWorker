import {test} from 'node:test';
import assert from 'node:assert/strict';
import {accountScript,accountPanel} from '../src/account-ui.ts';

function fixture(state){
 const nodes=new Map(),calls=[],messages=[];let confirmResult=true,finishCreate;
 const node=()=>({children:[],className:'',disabled:false,checked:false,value:'',textContent:'',append(...items){this.children.push(...items)},replaceChildren(){this.children=[]},setAttribute(k,v){this[k]=v},querySelectorAll(){return this.children}});
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)};
 const document={createElement:()=>node()};let refreshAccount;
 const api=async(path,data)=>{calls.push({path,data});return {flow:'flow',options:{challenge:'challenge',user:{id:'identity'},excludeCredentials:[]},ok:true,notification:'failed'}};
 const memberText=(parent,tag,text)=>{const item=node();item.textContent=text;parent.append(item);return item};
 const credentials={create:()=>new Promise(resolve=>finishCreate=resolve),get:async()=>null};
 const exports=new Function('$','fetch','document','api','say','memberText','navigator','bytes','attestationJSON','assertionJSON','refresh','confirm',accountScript+';return {refreshAccount,accountAction};')(get,async()=>({ok:true,json:async()=>state}),document,api,message=>messages.push(message),memberText,{credentials},x=>x,x=>x,x=>x,async()=>refreshAccount(),()=>confirmResult);
 refreshAccount=exports.refreshAccount;
 return {get,calls,messages,refreshAccount,confirm(value){confirmResult=value},finish(){finishCreate?.({id:'key'})}};
}
const key={id:'key',name:'<img src=x onerror=alert(1)>',created_at:10,last_used_at:null};
test('account panel and browser script parse; names render only as text',async()=>{
 new Function(accountScript);assert.match(accountPanel,/Passkeys & recovery/);
 const f=fixture({passkeys:[key],can_manage:true,can_add:true,role:'family'});await f.refreshAccount();
 const row=f.get('passkeysList').children[0];assert.equal(row.children[0].textContent,key.name);assert.equal(row.children[4].textContent,'Save name');assert.equal(row.children[5].disabled,true); // Cannot remove final key.
});
test('stale/email-only administrator cannot edit recovery or passkeys in UI',async()=>{
 const f=fixture({passkeys:[key],can_manage:false,can_add:false,role:'admin'});await f.refreshAccount();
 for(const id of ['emailRecovery','saveRecovery','addPasskey','passkeyName'])assert.equal(f.get(id).disabled,true);
 assert.match(f.get('recoveryHelp').textContent,/cannot change administrator passkeys/);
});
test('canceling removal or recovery confirmation sends no mutation',async()=>{
 const f=fixture({passkeys:[key,{...key,id:'second'}],can_manage:true,can_add:true,role:'family'});await f.refreshAccount();f.confirm(false);
 f.get('passkeysList').children[0].children[5].onclick();f.get('emailRecovery').checked=true;f.get('saveRecovery').onclick();
 assert.equal(f.calls.length,0);assert.equal(f.get('emailRecovery').checked,false);
});
test('repeated add clicks coalesce and notification failure is explicit',async()=>{
 const f=fixture({passkeys:[key],can_manage:true,can_add:true,role:'family'});await f.refreshAccount();f.get('passkeyName').value='Backup';
 const first=f.get('addPasskey').onclick();await new Promise(resolve=>setImmediate(resolve));const second=f.get('addPasskey').onclick();f.finish();await Promise.all([first,second]);
 assert.deepEqual(f.calls.map(c=>c.path),['/api/account/passkeys/options','/api/account/passkeys/verify']);assert.match(f.messages[0],/delivery could not be confirmed/);
});
