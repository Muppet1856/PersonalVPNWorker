import {test} from 'node:test';
import assert from 'node:assert/strict';
import {managementScript} from '../src/admin-ui.ts';

const apps=[{id:'chat.example.com',name:'Chat'},{id:'git.example.com',name:'Git'}];
const member=(id,grants=[],active=1)=>({id,name:id,email:id+'@example.com',role:'family',active,granted_apps:grants,allowed_apps:active?grants:[],access_revision:3,passkey_count:1,session_count:1});
function fixture(users=[member('Alice'),member('Bob',['git.example.com'],0)]){
 const nodes=new Map(),calls=[],messages=[];let confirmation=true,mutationError,canManage=true,verifications=0;
 function node(tag='div'){
  return {tag,children:[],disabled:false,hidden:false,value:'',checked:false,textContent:'',append(...items){this.children.push(...items)},replaceChildren(){this.children=[]},setAttribute(k,v){this[k]=v},querySelectorAll(selector){const tags=selector.split(',');return this.children.flatMap(child=>[...(tags.includes(child.tag)?[child]:[]),...child.querySelectorAll(selector)]);}};
 }
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)};
 get('userStatus').value='all';get('userService').value='all';get('management').append(get('usersList'),get('invitesList'));
 const fetch=async path=>({ok:true,json:async()=>path==='/api/admin/users'?{users,apps}:path==='/api/account'?{can_manage:canManage}:{invitations:[]}});
 let refreshAdmin;
 const exports=new Function('$','fetch','document','api','say','refresh','confirm','window','verifyPasskey',managementScript+';return {refreshAdmin,clearAdmin};')(get,fetch,{createElement:node},async(path,data)=>{calls.push({path,data});if(mutationError)throw Error(mutationError);const user=users.find(user=>user.id===data.user_id);if(data.action==='set_apps'){user.granted_apps=[...data.allowed_apps];user.access_revision++;}return {changed:true}},message=>messages.push(message),async()=>refreshAdmin(),()=>confirmation,{addEventListener(){}},async()=>{verifications++;canManage=true;});
 refreshAdmin=exports.refreshAdmin;
 return {get,users,calls,messages,refreshAdmin,clearAdmin:exports.clearAdmin,confirm(value){confirmation=value},fail(message){mutationError=message},stale(){canManage=false},get verifications(){return verifications}};
}
const buttons=row=>row.querySelectorAll('button');
const checks=row=>row.querySelectorAll('input');
const button=(row,label)=>buttons(row).find(node=>node.textContent===label);
const toggle=(row,index)=>{const input=checks(row)[index];input.checked=!input.checked;input.onchange();};

test('management renders saved grants for disabled users and treats names as text',async()=>{
 const f=fixture([member('<img src=x onerror=alert(1)>'),member('Bob',['git.example.com'],0)]);await f.refreshAdmin();
 const [alice,bob]=f.get('usersList').children;assert.equal(alice.children[0].textContent,f.users[0].name);
 assert.deepEqual(checks(bob).map(input=>input.checked),[false,true]);assert.equal(button(bob,'Save service access').disabled,true);
 toggle(bob,0);assert.equal(button(bob,'Save service access').disabled,false);
 await button(bob,'Save service access').onclick();
 assert.deepEqual(f.calls[0].data,{user_id:'Bob',action:'set_apps',allowed_apps:['chat.example.com','git.example.com'],expected_access_revision:3});
});

test('search, status and saved-service filters combine without dropping edits',async()=>{
 const f=fixture();await f.refreshAdmin();const [alice,bob]=f.get('usersList').children;toggle(alice,0);
 f.get('userSearch').value='BOB@';f.get('userSearch').oninput();assert.equal(alice.hidden,true);assert.equal(bob.hidden,false);
 f.get('userStatus').value='active';f.get('userStatus').onchange();assert.equal(bob.hidden,true);assert.equal(f.get('noUsers').hidden,false);
 f.get('userSearch').value='';f.get('userStatus').value='all';f.get('userService').value='git.example.com';f.get('userService').onchange();assert.equal(alice.hidden,true);assert.equal(bob.hidden,false);
 f.get('userService').value='none';f.get('userService').onchange();assert.equal(alice.hidden,false);assert.equal(bob.hidden,true);assert.equal(checks(alice)[0].checked,true);
});

test('canceling a grant save leaves the draft and makes no mutation',async()=>{
 const f=fixture();await f.refreshAdmin();const alice=f.get('usersList').children[0];toggle(alice,0);f.confirm(false);
 await button(alice,'Save service access').onclick();assert.equal(f.calls.length,0);assert.equal(checks(alice)[0].checked,true);assert.equal(button(alice,'Save service access').disabled,false);
 await f.get('refreshUsers').onclick();assert.equal(f.get('usersList').children[0],alice);
});

test('save failure preserves edits and their revision for conflict review',async()=>{
 const f=fixture();await f.refreshAdmin();const alice=f.get('usersList').children[0];toggle(alice,0);f.fail('Access changed since this page was loaded');
 await button(alice,'Save service access').onclick();assert.match(f.messages.at(-1),/Access changed/);assert.equal(checks(alice)[0].checked,true);
 f.users[0].access_revision=8;await f.refreshAdmin();await button(f.get('usersList').children[0],'Save service access').onclick();assert.equal(f.calls.at(-1).data.expected_access_revision,3);
});

test('saving one person keeps another draft; a stale admin verifies before mutation',async()=>{
 const f=fixture();await f.refreshAdmin();let [alice,bob]=f.get('usersList').children;toggle(alice,0);toggle(bob,0);f.stale();
 await button(alice,'Save service access').onclick();assert.equal(f.verifications,1);
 [alice,bob]=f.get('usersList').children;assert.equal(button(alice,'Save service access').disabled,true);assert.equal(button(bob,'Save service access').disabled,false);assert.equal(checks(bob)[0].checked,true);
 await button(bob,'Reset changes').onclick();assert.equal(checks(f.get('usersList').children[1])[0].checked,false);
});

test('administrator grants cannot be edited and clearing administration removes its catalog',async()=>{
 const f=fixture([{...member('Admin',apps.map(app=>app.id)),role:'admin'}]);await f.refreshAdmin();assert.equal(checks(f.get('usersList').children[0]).length,0);
 f.clearAdmin();for(const id of ['usersList','invitesList','userService'])assert.equal(f.get(id).children.length,0);
});
