import {it} from 'vitest';
import assert from 'node:assert/strict';
import {lstatSync,mkdirSync,mkdtempSync,readFileSync,readdirSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {applyPlan,planPermissions,planEnvRefs,planPinVersions} from '../src/fixes.js';

function fixture(run: (root:string,outside:string)=>void) {
 const root=mkdtempSync(join(tmpdir(),'sg-p0-'));
 const outside=mkdtempSync(join(tmpdir(),'sg-outside-'));
 const old=process.env.MCP_SECURITY_HOME;
 process.env.MCP_SECURITY_HOME=join(root,'backup-home');
 try {run(root,outside);}finally{if(old===undefined)delete process.env.MCP_SECURITY_HOME;else process.env.MCP_SECURITY_HOME=old;rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
}
it('rejects .claude directory escape before planning and preserves external canary',()=>fixture((root,outside)=>{
 writeFileSync(join(outside,'settings.json'),'{}');symlinkSync(outside,join(root,'.claude'),'junction');
 assert.throws(()=>planPermissions(root,['mcp__x__write']),/symlink/i);
 assert.equal(readFileSync(join(outside,'settings.json'),'utf8'),'{}');
}));
it('rejects target-file symlink including dangling symlink',()=>fixture((root,outside)=>{
 mkdirSync(join(root,'.claude'));symlinkSync(join(outside,'missing'),join(root,'.claude/settings.json'),'file');
 assert.throws(()=>planPermissions(root,['x']),/symlink/i);assert.deepEqual(readdirSync(outside),[]);
}));
it('all .mcp planners reject a symlinked source',async()=>{
 const root=mkdtempSync(join(tmpdir(),'sg-p0-'));const outside=mkdtempSync(join(tmpdir(),'sg-outside-'));
 try{writeFileSync(join(outside,'config.json'),'{}');symlinkSync(join(outside,'config.json'),join(root,'.mcp.json'),'file');assert.throws(()=>planEnvRefs(root),/symlink/i);await assert.rejects(planPinVersions(root,[]),/symlink/i);}finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});
it('preexisting predictable temporary symlink never receives file contents',()=>fixture((root,outside)=>{
 mkdirSync(join(root,'.claude'));writeFileSync(join(outside,'canary'),'unchanged');
 symlinkSync(join(outside,'canary'),join(root,'.claude/settings.json.mcpsec-tmp'),'file');
 const result=applyPlan(planPermissions(root,['x']));assert.equal(result.written.length,1);
 assert.equal(readFileSync(join(outside,'canary'),'utf8'),'unchanged');
 assert.equal(lstatSync(join(root,'.claude/settings.json.mcpsec-tmp')).isSymbolicLink(),true);
 assert.equal(readdirSync(join(root,'.claude')).filter(x=>x.startsWith('.mcpsec-')).length,0);
 if(process.platform!=='win32')assert.equal(lstatSync(join(root,'.claude/settings.json')).mode&0o777,0o600);
}));
it('revalidates directory after approval and refuses substituted symlink',()=>fixture((root,outside)=>{
 const plan=planPermissions(root,['x']);symlinkSync(outside,join(root,'.claude'),'junction');
 assert.throws(()=>applyPlan(plan),/symlink/i);assert.deepEqual(readdirSync(outside),[]);
}));
it('changed reviewed contents produce conflict, without overwrite or backup',()=>fixture((root)=>{
 mkdirSync(join(root,'.claude'));const target=join(root,'.claude/settings.json');writeFileSync(target,'{"model":"initial"}');
 const plan=planPermissions(root,['x']);writeFileSync(target,'{"model":"changed"}');
 assert.throws(()=>applyPlan(plan),/conflict/i);assert.equal(readFileSync(target,'utf8'),'{"model":"changed"}');
 assert.equal(readdirSync(root).includes('backup-home'),false);
}));
it('target appearing after missing-target review causes conflict',()=>fixture((root)=>{
 const plan=planPermissions(root,['x']);mkdirSync(join(root,'.claude'));writeFileSync(join(root,'.claude/settings.json'),'{}');
 assert.throws(()=>applyPlan(plan),/conflict/i);assert.equal(readFileSync(join(root,'.claude/settings.json'),'utf8'),'{}');
}));
it('rejects manually redirected or unversioned fix plan',()=>fixture((root,outside)=>{
 const plan=planPermissions(root,['x']);plan.changes[0].path=join(outside,'settings.json');
 assert.throws(()=>applyPlan(plan),/inside/i);assert.deepEqual(readdirSync(outside),[]);
 assert.throws(()=>applyPlan({changes:[{path:join(root,'.mcp.json'),edits:[],content:'{}'} as any],notes:[]}),/replan/i);
}));
it('exclusive target lock refuses contention without touching target',()=>fixture((root)=>{
 const plan=planPermissions(root,['x']);mkdirSync(join(root,'.claude'));writeFileSync(join(root,'.claude/settings.json.mcpsec-lock'),'held');
 assert.throws(()=>applyPlan(plan),/EEXIST/);assert.equal(readFileSync(join(root,'.claude/settings.json.mcpsec-lock'),'utf8'),'held');
 assert.equal(readdirSync(join(root,'.claude')).includes('settings.json'),false);
}));
it('refuses symlink backup directory without leaking original contents',()=>fixture((root,outside)=>{
 mkdirSync(join(root,'backup-home'));symlinkSync(outside,join(root,'backup-home/backups'),'junction');
 mkdirSync(join(root,'.claude'));writeFileSync(join(root,'.claude/settings.json'),'{}');
 assert.throws(()=>applyPlan(planPermissions(root,['x'])),/symlink/i);assert.deepEqual(readdirSync(outside),[]);
 assert.equal(readFileSync(join(root,'.claude/settings.json'),'utf8'),'{}');
}));
it('backups and target contents are private and no temporary files remain',()=>fixture((root)=>{
 mkdirSync(join(root,'.claude'));writeFileSync(join(root,'.claude/settings.json'),'{}');
 const result=applyPlan(planPermissions(root,['x']));assert.equal(readFileSync(result.backups[0],'utf8'),'{}');
 if(process.platform!=='win32')assert.equal(lstatSync(result.backups[0]).mode&0o777,0o600);
 assert.equal(readdirSync(join(root,'.claude')).filter(x=>x.includes('mcpsec')).length,0);
}));

it('multiple reviewed updates receive separate backups',()=>fixture((root)=>{
 mkdirSync(join(root,'.claude'));writeFileSync(join(root,'.claude/settings.json'),'{}');
 const first=applyPlan(planPermissions(root,['a']));const second=applyPlan(planPermissions(root,['b']));
 assert.notEqual(first.backups[0],second.backups[0]);assert.equal(readFileSync(first.backups[0],'utf8'),'{}');
 assert.match(readFileSync(second.backups[0],'utf8'),/a/);
}));
