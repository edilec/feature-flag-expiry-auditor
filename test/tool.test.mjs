import test from 'node:test';
import assert from 'node:assert/strict';
import { auditFlags, TOOL_ID, LIMITS, RULES } from '../src/index.mjs';
import { runCli } from '../src/cli.mjs';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy = { schemaVersion:'1', asOf:'2026-09-26T00:00:00Z', staleAfterDays:30 };
const flag = { key:'synthetic-flag', owner:'team-a', expiresAt:'2026-10-01T00:00:00Z', variants:[{ name:'on',lastUsedAt:'2026-09-25T00:00:00Z' }], cleanupDependencies:['code-callers'] };
const flags = { schemaVersion:'1',complete:true,flags:[flag] };
const references = { schemaVersion:'1',complete:true,references:[{ flagKey:'synthetic-flag',file:'src/flags.mjs',line:12 }] };
const audit = (f=flags,r=references,p=policy) => auditFlags(f,r,p);

test('owned unexpired flag with fresh variant, cleanup record and resolved local reference passes', () => {
  const report=audit(); assert.equal(TOOL_ID,'feature-flag-expiry-auditor');assert.equal(report.status,'pass');assert.equal(report.summary.checked,1);
  assert.equal(JSON.stringify(report).includes('synthetic-flag'),false);
});

test('expired flag with remaining reference fails and locates source ordinal', () => {
  const expired={...flag,expiresAt:'2026-09-25T00:00:00Z'};
  const report=audit({...flags,flags:[expired]});
  assert.equal(report.status,'fail');
  assert.ok(report.findings.some(f=>f.ruleId==='expired-flag-referenced'&&f.location.file==='@references'&&f.location.pointer==='/references/0'));
  assert.equal(JSON.stringify(report).includes('src/flags.mjs'),false);
});

test('missing owner, stale variant, and undocumented cleanup fail', () => {
  const noOwner={...flag,owner:''};assert.ok(audit({...flags,flags:[noOwner]}).findings.some(f=>f.ruleId==='owner-missing'));
  const stale={...flag,variants:[{name:'on',lastUsedAt:'2026-08-01T00:00:00Z'}]};assert.ok(audit({...flags,flags:[stale]}).findings.some(f=>f.ruleId==='variant-stale'));
  const noCleanup={...flag,cleanupDependencies:[]};assert.ok(audit({...flags,flags:[noCleanup]}).findings.some(f=>f.ruleId==='cleanup-undocumented'));
});

test('partial or ambiguous evidence on either side cannot pass', () => {
  assert.equal(audit({...flags,complete:false}).status,'incomplete');
  assert.equal(audit(flags,{...references,complete:false}).status,'incomplete');
  assert.equal(audit({...flags,flags:[{...flag,variants:[{name:'on',lastUsedAt:null}]}]}).status,'incomplete');
  assert.equal(audit(flags,{...references,references:[{flagKey:'unknown',file:'src/flags.mjs',line:12}]}).status,'incomplete');
});

test('flag/reference/variant and depth N/N+1, injected deadline', () => {
  const manyFlags=n=>({...flags,flags:Array.from({length:n},(_,i)=>({...flag,key:`flag-${i}`}))});
  assert.equal(audit(manyFlags(LIMITS.flags),{...references,references:[]}).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(manyFlags(LIMITS.flags+1),references).findings.some(f=>f.ruleId==='limit-exceeded'));
  const manyRefs=n=>({...references,references:Array.from({length:n},(_,i)=>({flagKey:flag.key,file:'src/flags.mjs',line:i+1}))});
  assert.equal(audit(flags,manyRefs(LIMITS.references)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(flags,manyRefs(LIMITS.references+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
  const manyVariants=n=>({...flags,flags:[{...flag,variants:Array.from({length:n},(_,i)=>({name:`variant-${i}`,lastUsedAt:'2026-09-25T00:00:00Z'}))}]});
  assert.equal(audit(manyVariants(LIMITS.variants)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(manyVariants(LIMITS.variants+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
  const deep=n=>{const d=structuredClone(flags);let x=d;for(let i=0;i<n;i++){x.extra={};x=x.extra;}return d;};
  assert.equal(audit(deep(16)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(deep(17)).findings.some(f=>f.ruleId==='limit-exceeded'));
  assert.equal(auditFlags(flags,references,policy,{now:()=>5000,deadline:5000}).status,'pass');
  assert.equal(auditFlags(flags,references,policy,{now:()=>5001,deadline:5000}).status,'incomplete');
});

test('CLI confines all reads, rejects duplicate JSON keys, and enforces byte N/N+1', () => {
  const root=mkdtempSync(join(tmpdir(),'flags-')),outside=mkdtempSync(join(tmpdir(),'flags-out-'));
  const args=['--root',root,'--policy','policy.json','--flags','flags.json','--references','refs.json'];
  const capture=()=>{let stdout='',stderr='';return{io:{stdout:{write:s=>{stdout+=s;}},stderr:{write:s=>{stderr+=s;}}},get stdout(){return stdout;},get stderr(){return stderr;}};};
  try{
    const base={'policy.json':JSON.stringify(policy),'flags.json':JSON.stringify(flags),'refs.json':JSON.stringify(references)};
    for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);
    let o=capture();assert.equal(runCli(args,o.io),0);assert.equal(JSON.parse(o.stdout).status,'pass');
    writeFileSync(join(root,'refs.json'),base['refs.json'].replace('"complete":true','"compl\\u0065te":false,"complete":true'));
    o=capture();assert.equal(runCli(args,o.io),2);assert.equal(JSON.parse(o.stdout).status,'incomplete');
    writeFileSync(join(outside,'refs.json'),base['refs.json']);symlinkSync(join(outside,'refs.json'),join(root,'linked.json'));
    o=capture();assert.equal(runCli(['--root',root,'--policy','policy.json','--flags','flags.json','--references','linked.json'],o.io),2);assert.equal(o.stdout,'');
    o=capture();assert.equal(runCli(['--root',join(root,'policy.json'),'--policy','policy.json','--flags','flags.json','--references','refs.json'],o.io),2);assert.equal(o.stdout,'');
    for(const [file,limit] of [['policy.json',LIMITS.policyBytes],['flags.json',LIMITS.flagsBytes],['refs.json',LIMITS.referencesBytes]]){
      for(const delta of [0,1]){for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);const raw=base[file];writeFileSync(join(root,file),raw+' '.repeat(limit+delta-Buffer.byteLength(raw)));o=capture();runCli(args,o.io);if(file==='policy.json')assert.equal(o.stdout==='',delta===1);else assert.equal(JSON.parse(o.stdout).findings.some(f=>f.ruleId==='limit-exceeded'),delta===1);}
    }
  }finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});

test('severity table is pinned',()=>{assert.deepEqual(RULES,{'policy-invalid':'warning','flags-invalid':'warning','references-invalid':'warning','export-incomplete':'warning','variant-unknown':'warning','reference-unknown':'warning','limit-exceeded':'warning','input-unreadable':'warning','owner-missing':'error','flag-expired':'error','expired-flag-referenced':'error','variant-stale':'error','cleanup-undocumented':'error'});});
