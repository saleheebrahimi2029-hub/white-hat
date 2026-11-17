import assert from 'node:assert/strict';
import http from 'node:http';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash,generateKeyPairSync,randomBytes,randomUUID,sign} from 'node:crypto';
import {mkdtempSync,copyFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';

const root=process.env.WH_AUDIT_REPO;
const {chromium}=createRequire(process.env.WH_PLAYWRIGHT_MODULE)('playwright');
const {createBff}=await import(pathToFileURL(resolve(root,'apps/web-bff/server.mjs')));
const {openStore}=await import(pathToFileURL(resolve(root,'apps/second-mind/server/store.mjs')));
const {Client}=createRequire(resolve(root,'apps/web-bff/package.json'))('pg');
const workspace=process.env.WH_AUDIT_WORKSPACE, tokens=JSON.parse(process.env.WH_AUDIT_TOKENS);
const db=new Client({connectionString:process.env.WH_AUDIT_DB});
const report=(check,details={})=>console.log(JSON.stringify({check,pass:true,...details}));
const secret='synthetic-private-marker';
async function rehearse() {
 const dir=mkdtempSync(join(tmpdir(),'whitehat-c2-'));
 try {
  const src=openStore(dir), stamp='2026-01-01T00:00:00Z';
  const mapped=randomUUID(), unmapped=randomUUID(), target=randomUUID();
  const putUser=src.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?)');
  const putDecision=src.prepare('INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?,?,?)');
  for (const [id,name] of [[mapped,'mapped'],[unmapped,'unmapped']])putUser.run(id,name,name,'synthetic','member',1,stamp);
  for (const [id,user] of [[target,mapped],[randomUUID(),unmapped]])putDecision.run(id,user,'Synthetic migrated',secret,'objective','context','notes','challenge','draft',stamp,stamp);
  src.exec('PRAGMA wal_checkpoint(TRUNCATE)');src.close();
  const copy=join(dir,'copy.sqlite');copyFileSync(join(dir,'second-mind.sqlite'),copy);
  const hash=()=>createHash('sha256').update(readFileSync(copy)).digest('hex');
  const before=hash(), reader=new DatabaseSync(copy,{readOnly:true});
  const rows=reader.prepare('SELECT * FROM challenges').all();reader.close();
  const mapping=new Map([[mapped,'alice']]);
  const accepted=rows.filter(x=>mapping.has(x.user_id));
  assert.equal(rows.length,2);assert.equal(accepted.length,1);
  const read=async()=> (await db.query('SELECT owner_subject,title,decision,objective,context,source_notes,mode FROM decisions WHERE workspace_id=$1 AND id=$2',[workspace,target])).rows;
  const write=async()=>{ for (const r of accepted)await db.query(
    'INSERT INTO decisions(workspace_id,id,owner_subject,title,decision,objective,context,source_notes,mode,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
    [workspace,r.id,mapping.get(r.user_id),r.title,r.decision,r.objective,r.context,r.source_notes,r.mode,r.created_at,r.updated_at]); };
  await db.query('BEGIN');await write();assert.equal((await read()).length,1);
  await db.query('ROLLBACK');assert.equal((await read()).length,0);
  await db.query('BEGIN');await write();await db.query('COMMIT');
  assert.deepEqual(await read(),[{owner_subject:'alice',title:'Synthetic migrated',decision:secret,objective:'objective',context:'context',source_notes:'notes',mode:'challenge'}]);
  assert.equal(hash(),before);
  report('sqlite_rehearsal',{source:2,committed:1,quarantined:1,reason:'unmapped_subject',rollbackAfterWrite:true,sourceCopySha256:before});
  return target;
 } finally {rmSync(dir,{recursive:true,force:true});}
}

const listen=server=>new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',()=>ok('http://127.0.0.1:'+server.address().port));});
const close=server=>new Promise(ok=>server.close(ok));
const json=(res,status,value)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(value));};
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...publicKey.export({format:'jwk'}),kid:'local-audit-key',alg:'RS256',use:'sig'};
const sha=x=>createHash('sha256').update(x).digest('base64url'), enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
let issuer, subject='alice', revocations=0;
const flows=new Map();
const idp=http.createServer(async(req,res)=>{
 const url=new URL(req.url,issuer);
 if(url.pathname==='/.well-known/openid-configuration')return json(res,200,{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/jwks',revocation_endpoint:issuer+'/revoke'});
 if(url.pathname==='/jwks')return json(res,200,{keys:[jwk]});
 if(url.pathname==='/authorize'){
  const p=url.searchParams, code=randomUUID();
  flows.set(code,{subject,challenge:p.get('code_challenge'),nonce:p.get('nonce')});
  const cb=new URL(p.get('redirect_uri'));cb.searchParams.set('state',p.get('state'));cb.searchParams.set('code',code);
  res.writeHead(302,{Location:cb.href});return res.end();
 }
 if(url.pathname==='/revoke'){revocations++;return json(res,200,{});}
 if(url.pathname==='/token'){
  let raw='';for await(const c of req)raw+=c;
  const p=new URLSearchParams(raw), code=p.get('code'), flow=flows.get(code);flows.delete(code);
  if(!flow||sha(p.get('code_verifier')||'')!==flow.challenge)return json(res,400,{error:'bad_pkce'});
  const now=Math.floor(Date.now()/1000);
  const message=enc({alg:'RS256',typ:'JWT',kid:jwk.kid})+'.'+enc({iss:issuer,aud:'audit-fixture',sub:flow.subject,nonce:flow.nonce,iat:now,exp:now+300});
  return json(res,200,{id_token:message+'.'+sign('RSA-SHA256',Buffer.from(message),privateKey).toString('base64url'),access_token:tokens[flow.subject],refresh_token:randomUUID(),token_type:'Bearer',expires_in:230});
 }
 return json(res,404,{});
});
const browsers=[];
let bff;
try {
 await db.connect();
 await db.query(readFileSync(resolve(root,'apps/web-bff/db/session-store.sql'),'utf8'));
 const imported=await rehearse();
 if(process.env.WH_AUDIT_MIGRATION_ONLY==="1"){await db.end();process.exit(0);}
 issuer=await listen(idp);
 const placeholder=http.createServer(), origin=await listen(placeholder);await close(placeholder);
 ({server:bff}=createBff({env:{
  WH_WEB_ORIGIN:origin, WH_API_BASE:process.env.WH_AUDIT_API, WH_OIDC_ISSUER:issuer,
  WH_OIDC_CLIENT_ID:'audit-fixture',WH_DEV_INSECURE_HTTP:'1',
  WH_WEB_SESSION_DATABASE_URL:process.env.WH_AUDIT_DB,WH_WEB_SESSION_KEYS:randomBytes(32).toString('base64')
 }}));
 await new Promise((ok,fail)=>{bff.once('error',fail);bff.listen(Number(new URL(origin).port),'127.0.0.1',ok);});
 const ws='/bff/api/v1/workspaces/'+workspace;
 const open=async (id, viewport)=>{
  subject=id;
  const browser=await chromium.launch({
   executablePath:process.env.WH_BROWSER_BIN||chromium.executablePath(),
   headless:true,args:['--no-sandbox','--single-process','--no-zygote']
  });
  browsers.push(browser);
  const context=await browser.newContext({ viewport }), page=await context.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(origin);await page.locator('a[href="/auth/login"]').click();
  await page.waitForFunction(s=>document.querySelector('.wh-side-bottom b')?.textContent===s,id);
  assert.ok((await context.cookies()).some(x=>x.name==='wh_session_dev'&&x.httpOnly));
  return page;
 };
 const get=(page,path)=>page.request.get(origin+path);
 const nav=(page,key)=>page.locator('nav [data-screen="'+key+'"]');
 const owner=await open('alice'), support=await open('support'), admin=await open('admin'), outside=await open('outside');
 const member=await open('member',{width:390,height:844});
 const proposals=await get(owner,ws+'/admin/plan-preview');assert.equal(proposals.status(),200);
 const proposalBody=await proposals.json();assert.equal(proposalBody.billing_enabled,false);
 assert.equal(proposalBody.items.length,4);assert.ok(proposalBody.items.every(x=>x.revenue_floor_usd_micros===null));
 for(const page of [support,member])assert.equal((await get(page,ws+'/admin/plan-preview')).status(),403);
 assert.equal((await get(outside,ws+'/admin/plan-preview')).status(),404);
 report('commercial_proposals_are_scoped_and_inactive',{billingEnabled:false,privateCostsNotInvented:true});
 // A transient boot failure must allow retry without claiming the user is signed out.
 for(const endpoint of ['/bff/session','/bff/api/v1/me']){
  await owner.route('**'+endpoint,route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'IDENTITY_PROVIDER_UNAVAILABLE'})}));
  await owner.reload();
  const retry=owner.getByRole('button',{name:'تلاش دوباره',exact:true});await retry.waitFor();
  assert.equal(await owner.locator('a[href="/auth/login"]').count(),0);
  await owner.unroute('**'+endpoint);
  await retry.focus();await owner.keyboard.press('Enter');
  await owner.waitForFunction(()=>document.querySelector('.wh-side-bottom b')?.textContent==='alice');
 }
 report('transient_boot_recovery',{sessionAndApiUnavailable:true,keyboardRetry:true,existingSessionRetained:true});
 assert.equal(await member.locator('html').getAttribute('dir'),'rtl');
 assert.ok(await member.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
 assert.equal(await nav(member,'usage').count(),0);
 assert.equal(await nav(member,'members').count(),0);
 assert.equal(await nav(support,'members').count(),0);
 assert.equal(await nav(support,'usage').count(),0);
 assert.equal(await nav(support,'history').count(),0);
 assert.equal(await nav(admin,'members').count(),0);
 await support.getByRole('heading',{name:'فضای پشتیبانی'}).waitFor();
 await nav(owner,'history').focus();
 await owner.keyboard.press('Enter');
 assert.equal(await owner.evaluate(()=>document.activeElement.dataset.screen),'history');
 await owner.locator('[data-decision="'+imported+'"]').click();
 await owner.getByText(secret,{exact:true}).waitFor();

 // An edit made after the form is opened must be preserved when the stale form submits.
 const decisionPath=ws+'/decisions/'+imported;
 const beforeEdit=await (await get(owner,decisionPath)).json();
 await owner.locator('#edit').click();
 const editForm=owner.locator('#decision-form');
 await editForm.locator('[name=title]').fill('عنوان محلی آزمایشی');
 const {csrf}=await (await get(owner,'/bff/session')).json();
 const concurrentEdit=await owner.request.put(origin+decisionPath,{
  headers:{Origin:origin,'X-CSRF-Token':csrf},
  data:{title:'عنوان ثبت‌شدهٔ هم‌زمان',decision:beforeEdit.decision,objective:beforeEdit.objective,
   context:beforeEdit.context,source_notes:beforeEdit.source_notes,mode:beforeEdit.mode,expected_revision:beforeEdit.revision}
 });
 assert.equal(concurrentEdit.status(),200);
 const save=editForm.locator('[type=submit]');
 const [editResponse]=await Promise.all([
  owner.waitForResponse(response=>response.url()===origin+decisionPath&&response.request().method()==='PUT'),
  save.click()
 ]);
 assert.equal(editResponse.status(),409);
 assert.equal((await editResponse.json()).error,'REVISION_CONFLICT');
 assert.equal(editResponse.request().postDataJSON().expected_revision,beforeEdit.revision);
 await owner.locator('#toast').filter({hasText:'این تصمیم در جای دیگه تغییر کرده؛ اطلاعات رو تازه‌سازی کن.'}).waitFor();
 assert.equal(await editForm.locator('[name=title]').inputValue(),'عنوان محلی آزمایشی');
 assert.equal(await save.isEnabled(),true);
 const committed=await (await get(owner,decisionPath)).json();
 assert.equal(committed.title,'عنوان ثبت‌شدهٔ هم‌زمان');
 assert.equal(committed.revision,beforeEdit.revision+1);
 report('browser_revision_conflict',{status:409,staleFormRetained:true,concurrentEditPreserved:true});

 // The Kotlin fixture has already spent the single pilot attempt in this workspace.
 await nav(owner,'history').click();
 await owner.locator('[data-decision="'+imported+'"]').click();
 const quotaState=async()=> (await db.query(
  `SELECT (SELECT count(*)::int FROM runs WHERE workspace_id=$1) AS runs,
   (SELECT coalesce(sum(attempts),0)::int FROM workspace_pilot_usage WHERE workspace_id=$1) AS pilot_attempts,
   (SELECT coalesce(sum(attempts),0)::int FROM usage_counters WHERE workspace_id=$1) AS daily_attempts`,[workspace])).rows[0];
 const exhausted=await quotaState();
 assert.equal(exhausted.pilot_attempts,1);
 const analyze=owner.locator('#analyze');
 const [quotaResponse]=await Promise.all([
  owner.waitForResponse(response=>response.url()===origin+decisionPath+'/runs'&&response.request().method()==='POST'),
  analyze.click()
 ]);
 assert.equal(quotaResponse.status(),429);
 assert.equal((await quotaResponse.json()).error,'PILOT_LIMIT_REACHED');
 assert.equal(quotaResponse.request().postDataJSON().expected_revision,committed.revision);
 assert.ok((await quotaResponse.request().allHeaders())['idempotency-key']);
 await owner.locator('#toast').filter({hasText:'سهمیهٔ ماهانهٔ پایلوت این فضا تکمیل شده است.'}).waitFor();
 await owner.locator('#run-panel').getByText('هنوز اجرایی انتخاب نشده.',{exact:false}).waitFor();
 assert.equal(await analyze.isEnabled(),true);
 assert.deepEqual(await quotaState(),exhausted);
 report('browser_pilot_limit',{status:429,pilotAttempts:1,noRunOrUsageInserted:true});
 assert.equal(await nav(support,'incidents').count(),1);assert.equal(await nav(admin,'incidents').count(),0);
 assert.equal((await get(outside,ws+'/decisions/'+imported)).status(),404);
 const denied=await get(support,ws+'/decisions/'+imported);
 assert.ok([403,404].includes(denied.status()));assert.ok(!(await denied.text()).includes(secret));
 assert.equal((await get(support,ws+'/admin/costs')).status(),403);
 await nav(admin,'usage').click();
 await admin.getByText('جمع ثبت‌شده USD: 0.001250',{exact:true}).waitFor();
 assert.equal(await admin.locator('#cost-form').count(),0);
 await nav(owner,'members').click();
 const permission='[data-subject="support"][data-permission="READ_RUN_METRICS"]';
 const metrics=()=>get(support,ws+'/operations-metrics');
 assert.equal((await metrics()).status(),403);
 await owner.locator(permission+'[data-enable="true"]').click();
 await owner.locator(permission+'[data-enable="false"]').waitFor();
 assert.equal((await metrics()).status(),200);
 await owner.locator(permission+'[data-enable="false"]').click();
 await owner.locator(permission+'[data-enable="true"]').waitFor();
 assert.equal((await metrics()).status(),403);
 const form=owner.locator('#member-form');
 await form.locator('[name=subject]').fill('support');
 await form.locator('[name=role]').selectOption('SUPPORT');
 await form.locator('[name=active]').uncheck();
 await form.locator('[type=submit]').click();
 await owner.locator('#member-list li').filter({hasText:'support'}).getByText('غیرفعال',{exact:false}).waitFor();
 assert.equal((await metrics()).status(),404);
 await support.reload();
 await support.locator('.wh-side-bottom b').waitFor();
 assert.equal(await nav(support,'incidents').count(),0);

 await nav(owner,'usage').click();
 const pause=owner.getByRole('button',{name:'توقف ثبت تحلیل جدید'});
 await pause.click();
 await owner.getByRole('button',{name:'ازسرگیری تحلیل‌های جدید'}).waitFor();
 const settings=await (await get(owner,ws+'/analysis-settings')).json();
 assert.equal(settings.paused,true);
 await owner.getByRole('button',{name:'ازسرگیری تحلیل‌های جدید'}).click();
 await pause.waitFor();

 await nav(owner,'quality').click();
 const feedback=owner.getByRole('button',{name:'فعال‌کردن دریافت امتیاز'});
 await feedback.click();
 await owner.getByRole('button',{name:'توقف دریافت امتیاز'}).waitFor();
 assert.equal((await (await get(owner,ws+'/feedback-settings')).json()).enabled,true);
 await owner.getByRole('button',{name:'توقف دریافت امتیاز'}).click();
 await feedback.waitFor();
 const sessions=(await db.query('SELECT payload FROM wh_web_sessions')).rows;
 assert.ok(sessions.length>=5);
 assert.ok(sessions.every(x=>Object.values(tokens).every(token=>!x.payload.includes(token))));
 await owner.route('**/bff/logout',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'IDENTITY_PROVIDER_UNAVAILABLE'})}));
 await owner.locator('#logout').click();
 await owner.locator('#toast').filter({hasText:'سرویس ورود موقتاً'}).waitFor();
 assert.equal(await owner.locator('a[href="/auth/login"]').count(),0);
 assert.equal((await get(owner,'/bff/session')).status(),200);
 await owner.unroute('**/bff/logout');
 report('logout_failure_is_not_reported_as_success',{sessionStillActive:true,retryAvailable:true});
 for(const page of [owner,support,admin,member,outside]){
  await page.locator('#logout').click();await page.locator('a[href="/auth/login"]').waitFor();
  assert.equal((await get(page,'/bff/session')).status(),401);
 }
 assert.ok(revocations>=5);
 report('chromium_bff_and_postgres',{upstream:'real-ktor-with-synthetic-identity-and-provider',roles:['OWNER','SUPPORT','ADMIN','MEMBER','outside'],deprovisionedOpenSession:true,mobileRtl:true,keyboardNavigation:true,analysisAndFeedbackControls:true,privateDataIsolation:true,grantRevokeInSameSession:true,receiptRendered:true,encryptedSessions:true,logoutRevocation:true});
} finally {
 await Promise.all(browsers.map(browser=>browser.close()));
 if(bff)await close(bff);
 await close(idp);await db.end();
}
process.exit(0);
