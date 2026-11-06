export const managementPanel = `<div id="managementColumn" class="col-12" hidden><section id="management" class="card" hidden><div class="card-body p-4">
<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3"><div><h2 class="h5 card-title mb-1">User management</h2><p id="usersSummary" class="small text-secondary mb-0" aria-live="polite"></p></div><button id="refreshUsers" class="btn btn-sm btn-outline-secondary">Refresh users</button></div>
<p class="admin-note">Choose which services each person can open. New members start with no access. Services without permission are hidden from their portal and launcher. Administrators have access to every configured service.</p>
<div class="row g-3 mb-4"><div class="col-md-6"><label for="userSearch" class="form-label">Find a person</label><input id="userSearch" class="form-control" type="search" placeholder="Search name or email" autocomplete="off"></div><div class="col-md-3"><label for="userStatus" class="form-label">Account status</label><select id="userStatus" class="form-select"><option value="all">All accounts</option><option value="active">Active</option><option value="disabled">Disabled</option></select></div><div class="col-md-3"><label for="userService" class="form-label">Saved service access</label><select id="userService" class="form-select"><option value="all">All services</option><option value="none">No service access</option></select></div></div>
<div id="usersList" class="member-list" aria-live="polite"></div><p id="noUsers" class="text-secondary small mt-3" hidden>No people match these filters.</p>
<details class="mt-4"><summary class="small">When access changes take effect</summary><p class="admin-note mt-2 mb-0">Saving changed permissions signs the person out of this portal. Existing Cloudflare Access sessions must be revoked separately for immediate removal. Each service must have its matching Access claim policy configured. These settings control entry to a service; roles inside the service are managed there.</p></details>
<h3 class="h6 mt-4 pt-2 mb-3">Pending invitations</h3><div id="invitesList" class="member-list" aria-live="polite"></div></div></section></div>`;

// Only administrators fetch the service catalog. User-provided content is always text.
export const managementScript = `
let adminRows=[],adminDrafts=new Map(),adminBusy=false;
function memberText(parent,tag,text){const node=document.createElement(tag);node.textContent=text;parent.append(node);return node;}
function clearAdmin(){adminRows=[];adminDrafts.clear();$('usersList').replaceChildren();$('invitesList').replaceChildren();$('userService').replaceChildren();$('usersSummary').textContent='';}
function memberButton(parent,label,action,danger=false){
 const button=document.createElement('button');button.type='button';button.textContent=label;button.className=danger?'btn btn-sm btn-outline-danger':'btn btn-sm btn-outline-secondary';
 button.onclick=async()=>{if(adminBusy)return;adminBusy=true;const controls=[...$('management').querySelectorAll('button,input,select')];const previous=controls.map(node=>node.disabled);controls.forEach(node=>node.disabled=true);try{if(await action()!==false)await refresh()}catch(e){say(String(e))}finally{adminBusy=false;controls.forEach((node,index)=>node.disabled=previous[index]);}};
 parent.append(button);return button;
}
async function readAdmin(path){const r=await fetch(path,{credentials:'same-origin'});const data=await r.json();if(!r.ok)throw Error(data.error||'Could not load administration data');return data;}
function filterUsers(){
 const query=$('userSearch').value.trim().toLowerCase(),status=$('userStatus').value,service=$('userService').value;let visible=0;
 for(const {user,row} of adminRows){const grants=user.granted_apps||[];row.hidden=!(user.name+' '+user.email).toLowerCase().includes(query)||(status==='active'&&!user.active)||(status==='disabled'&&!!user.active)||(service==='none'&&grants.length>0)||(service!=='all'&&service!=='none'&&!grants.includes(service));if(!row.hidden)visible++;}
 $('noUsers').hidden=visible>0;$('usersSummary').textContent=visible+' of '+adminRows.length+' people shown';
}
async function verifyAdminForChange(){const state=await readAdmin('/api/account');if(!state.can_manage)await verifyPasskey();}
async function refreshAdmin(){
 const [members,pending]=await Promise.all([readAdmin('/api/admin/users'),readAdmin('/api/admin/invites')]);
 $('usersList').replaceChildren();$('invitesList').replaceChildren();adminRows=[];
 const selected=$('userService').value;$('userService').replaceChildren();
 for(const [value,label] of [['all','All services'],['none','No service access'],...(members.apps||[]).map(app=>[app.id,app.name])]){const option=memberText($('userService'),'option',label);option.value=value;}
 $('userService').value=['all','none',...(members.apps||[]).map(app=>app.id)].includes(selected)?selected:'all';
 for(const user of members.users){
  const row=document.createElement('section');row.className='member';memberText(row,'strong',user.name);memberText(row,'p',user.email);
  memberText(row,'small',(user.role==='admin'?'Administrator':'Family member')+' · '+(user.active?'Active':'Disabled')+' · '+user.passkey_count+' passkey(s) · '+user.session_count+' portal session(s)');
  memberText(row,'small',user.last_sign_in?'Last passkey sign-in: '+new Date(user.last_sign_in*1000).toLocaleString():'No passkey sign-in recorded');
  if(user.role==='admin')memberText(row,'p','All services · administrator access');
  else{
   const saved=user.granted_apps||[],draft=adminDrafts.get(user.id),initial=draft?draft.ids:saved,revision=draft?draft.revision:user.access_revision;
   const permissions=document.createElement('fieldset');permissions.className='mt-3';const legend=memberText(permissions,'legend','Service access');legend.className='h6';const checks=[];
   for(const app of members.apps||[]){const label=document.createElement('label');label.className='form-check small my-2';const input=document.createElement('input');input.type='checkbox';input.className='form-check-input';input.value=app.id;input.checked=initial.includes(app.id);const copy=document.createElement('span');copy.className='form-check-label';memberText(copy,'span',app.name);memberText(copy,'small',app.id);label.append(input,copy);permissions.append(label);checks.push(input);}
   if(!checks.length)memberText(permissions,'p','No services are configured yet.');row.append(permissions);
   if(!user.active)memberText(row,'p','Account disabled. Saved permissions apply only after the account is enabled.');
   const status=memberText(row,'small','');status.setAttribute('role','status');
   const save=memberButton(row,'Save service access',async()=>{
    const ids=checks.filter(input=>input.checked).map(input=>input.value);
    if(!confirm('Update service access for '+user.email+'? They will be signed out of this portal. Existing Cloudflare Access sessions must be revoked separately.'))return false;
    await verifyAdminForChange();const result=await api('/api/admin/users',{user_id:user.id,action:'set_apps',allowed_apps:ids,expected_access_revision:revision});adminDrafts.delete(user.id);
    say(result.changed===false?'Service access is already up to date.':'Service access saved. Existing Cloudflare Access sessions must be revoked separately for immediate removal.');
   });save.className='btn btn-sm btn-primary';
   const reset=memberButton(row,'Reset changes',async()=>{adminDrafts.delete(user.id);});
   function update(){const ids=checks.filter(input=>input.checked).map(input=>input.value);const dirty=ids.length!==saved.length||ids.some(id=>!saved.includes(id));if(dirty)adminDrafts.set(user.id,{ids,revision});else adminDrafts.delete(user.id);save.disabled=reset.disabled=!dirty;status.textContent=(dirty?'Unsaved changes · ':'')+ids.length+' of '+checks.length+' services selected';}
   checks.forEach(input=>input.onchange=update);update();
   memberButton(row,user.active?'Disable account':'Enable account',async()=>{if(user.active&&!confirm('Disable '+user.email+' and sign out their portal sessions?'))return false;await verifyAdminForChange();await api('/api/admin/users',{user_id:user.id,action:user.active?'disable':'enable'});say(user.active?'Account disabled. Revoke existing Cloudflare Access sessions separately.':'Account enabled with its saved service permissions.');},!!user.active);
  }
  memberButton(row,'Sign out portal sessions',async()=>{if(!confirm('Sign out all portal sessions for '+user.email+'? Cloudflare Access sessions are managed separately.'))return false;await verifyAdminForChange();await api('/api/admin/users',{user_id:user.id,action:'revoke_sessions'});say('Portal sessions revoked.');});
  $('usersList').append(row);adminRows.push({user,row});
 }
 for(const invitation of pending.invitations){const row=document.createElement('section');row.className='member';memberText(row,'strong',invitation.email);memberText(row,'small','Expires: '+new Date(invitation.expires_at*1000).toLocaleString());if(invitation.role!=='admin')memberButton(row,'Revoke invitation',async()=>{if(!confirm('Revoke the unused invitation for '+invitation.email+'?'))return false;await verifyAdminForChange();await api('/api/admin/invites/revoke',{invitation_id:invitation.id});say('Invitation revoked.');},true);$('invitesList').append(row);}
 if(!pending.invitations.length)memberText($('invitesList'),'small','No pending invitations.');
 if(members.limited)memberText($('usersList'),'small','Showing the first 200 users. Filters apply to these users.');if(pending.limited)memberText($('invitesList'),'small','Showing the first 200 invitations.');filterUsers();
}
$('userSearch').oninput=filterUsers;$('userStatus').onchange=filterUsers;$('userService').onchange=filterUsers;
$('refreshUsers').onclick=async()=>{if(adminBusy)return;if(adminDrafts.size&&!confirm('Discard unsaved service access changes and refresh users?'))return;try{adminDrafts.clear();await refreshAdmin();say('User list refreshed.')}catch(e){say(String(e))}};
window.addEventListener('beforeunload',event=>{if(adminDrafts.size){event.preventDefault();event.returnValue='';}});
`;
