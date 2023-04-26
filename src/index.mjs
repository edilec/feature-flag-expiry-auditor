export const TOOL_ID='feature-flag-expiry-auditor';
export const LIMITS=Object.freeze({policyBytes:65536,flagsBytes:1048576,referencesBytes:1048576,flags:1000,references:10000,variants:5000,depth:16,milliseconds:5000});
export const RULES=Object.freeze({'policy-invalid':'warning','flags-invalid':'warning','references-invalid':'warning','export-incomplete':'warning','variant-unknown':'warning','reference-unknown':'warning','limit-exceeded':'warning','input-unreadable':'warning','owner-missing':'error','flag-expired':'error','expired-flag-referenced':'error','variant-stale':'error','cleanup-undocumented':'error'});
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const only=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
const slug=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,127}$/.test(x);
const relativeFile=x=>typeof x==='string'&&x.length>0&&x.length<=512&&!x.startsWith('/')&&!x.split('/').some(p=>p===''||p==='.'||p==='..')&&!/[\u0000-\u001f\u007f-\u009f\\\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(x);
const instant=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString().slice(0,19)===x.slice(0,19);
const cmp=(a,b)=>a<b?-1:a>b?1:0;
function depth(x){const stack=[[x,0,new Set()]];while(stack.length){const[v,n,a]=stack.pop();if(n>LIMITS.depth)return n;if(v&&typeof v==='object'){if(a.has(v))return LIMITS.depth+1;const next=new Set(a);next.add(v);for(const c of Object.values(v))stack.push([c,n+1,next]);}}return 0;}
export function validPolicy(p){return obj(p)&&only(p,['schemaVersion','asOf','staleAfterDays'])&&p.schemaVersion==='1'&&instant(p.asOf)&&Number.isSafeInteger(p.staleAfterDays)&&p.staleAfterDays>=1&&p.staleAfterDays<=3650;}
export function auditFlags(flagsDoc,referencesDoc,policy,{now=Date.now,deadline=now()+LIMITS.milliseconds}={}){
  const findings=[];
  const add=(ruleId,file,pointer,message)=>{if(!Object.hasOwn(RULES,ruleId))throw new Error('Unknown rule');findings.push({ruleId,severity:RULES[ruleId],message,location:{file,pointer}});};
  const finish=checked=>{findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));return{schemaVersion:'1',tool:TOOL_ID,status:findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':checked?'pass':'incomplete',summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};};
  if(!validPolicy(policy)){add('policy-invalid','@policy','','Flag policy is invalid.');return finish(0);}
  if(depth(flagsDoc)>LIMITS.depth){add('limit-exceeded','@flags','','Flag export JSON depth limit exceeded.');return finish(0);}
  if(depth(referencesDoc)>LIMITS.depth){add('limit-exceeded','@references','','Reference export JSON depth limit exceeded.');return finish(0);}
  if(!obj(flagsDoc)||!only(flagsDoc,['schemaVersion','complete','flags'])||flagsDoc.schemaVersion!=='1'||typeof flagsDoc.complete!=='boolean'||!Array.isArray(flagsDoc.flags)){add('flags-invalid','@flags','','Flag export shape is invalid.');return finish(0);}
  if(!obj(referencesDoc)||!only(referencesDoc,['schemaVersion','complete','references'])||referencesDoc.schemaVersion!=='1'||typeof referencesDoc.complete!=='boolean'||!Array.isArray(referencesDoc.references)){add('references-invalid','@references','','Reference export shape is invalid.');return finish(0);}
  if(flagsDoc.flags.length>LIMITS.flags){add('limit-exceeded','@flags','/flags','Flag record limit exceeded.');return finish(0);}
  if(referencesDoc.references.length>LIMITS.references){add('limit-exceeded','@references','/references','Reference record limit exceeded.');return finish(0);}
  if(!flagsDoc.complete)add('export-incomplete','@flags','/complete','Flag export declares partial coverage.');
  if(!referencesDoc.complete)add('export-incomplete','@references','/complete','Code reference export declares partial coverage.');
  if(!flagsDoc.flags.length){add('flags-invalid','@flags','/flags','No flag evidence was supplied.');return finish(0);}
  const refs=new Map();
  for(let i=0;i<referencesDoc.references.length;i++){
    if(now()>deadline){add('limit-exceeded','@references','','Evaluation deadline exceeded.');return finish(0);}
    const r=referencesDoc.references[i];
    if(!obj(r)||!only(r,['flagKey','file','line'])||!slug(r.flagKey)||!relativeFile(r.file)||!Number.isSafeInteger(r.line)||r.line<1){add('references-invalid','@references',`/references/${i}`,'Code reference identity or position is invalid.');continue;}
    if(!refs.has(r.flagKey))refs.set(r.flagKey,[]);refs.get(r.flagKey).push(i);
  }
  const seen=new Set();let variants=0;const asOf=Date.parse(policy.asOf),staleBefore=asOf-policy.staleAfterDays*86400000;
  for(let i=0;i<flagsDoc.flags.length;i++){
    if(now()>deadline){add('limit-exceeded','@flags','','Evaluation deadline exceeded.');return finish(i);}
    const f=flagsDoc.flags[i],at=`/flags/${i}`;
    if(!obj(f)||!only(f,['key','owner','expiresAt','variants','cleanupDependencies'])||!slug(f.key)||!instant(f.expiresAt)||!Array.isArray(f.variants)||!Array.isArray(f.cleanupDependencies)||seen.has(f.key)){add('flags-invalid','@flags',at,'Flag identity, expiry, variants, or cleanup documentation is invalid or duplicated.');continue;}
    seen.add(f.key);
    if(!slug(f.owner))add('owner-missing','@flags',`${at}/owner`,'Flag owner is missing or unusable.');
    if(!f.cleanupDependencies.length||!f.cleanupDependencies.every(slug))add('cleanup-undocumented','@flags',`${at}/cleanupDependencies`,'Cleanup dependencies are not documented with usable names.');
    variants+=f.variants.length;if(variants>LIMITS.variants){add('limit-exceeded','@flags','/flags','Variant record limit exceeded.');return finish(i);}
    if(!f.variants.length)add('variant-unknown','@flags',`${at}/variants`,'Flag has no variant evidence.');
    const variantNames=new Set();
    for(let j=0;j<f.variants.length;j++){
      const v=f.variants[j],vp=`${at}/variants/${j}`;
      if(!obj(v)||!only(v,['name','lastUsedAt'])||!slug(v.name)||!instant(v.lastUsedAt)||variantNames.has(v.name)||Date.parse(v.lastUsedAt)>asOf){add('variant-unknown','@flags',vp,'Variant identity or usage evidence is unknown.');continue;}
      variantNames.add(v.name);
      if(Date.parse(v.lastUsedAt)<staleBefore)add('variant-stale','@flags',vp,'Variant usage predates the allowed freshness window.');
    }
    if(Date.parse(f.expiresAt)<=asOf){
      const linked=refs.get(f.key)||[];
      if(!linked.length)add('flag-expired','@flags',`${at}/expiresAt`,'Flag expiry has passed.');
      for(const j of linked)add('expired-flag-referenced','@references',`/references/${j}`,'Expired flag still has a local code reference.');
    }
  }
  for(const [key,positions] of refs)if(!seen.has(key))for(const i of positions)add('reference-unknown','@references',`/references/${i}`,'Code reference cannot be matched to an exported flag.');
  return finish(flagsDoc.flags.length);
}
