import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync(new URL('../dashboard/index.html', import.meta.url),'utf8');
const js=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
const raw=js?.match(/const PROJECT = (\{[^\n]+\});\nconst \$=/)?.[1];
test('dashboard JavaScript parses and embeds valid source data',()=>{
 assert.ok(js);assert.doesNotThrow(()=>new vm.Script(js));
 assert.ok(raw,'Project JSON fixture missing');
 const p=JSON.parse(raw);assert.ok(p.title.length);assert.ok(p.rows.length>0);
 assert.equal(new Set(p.rows.map(x=>x.id)).size,p.rows.length,'IDs must be unique');
 assert.equal(p.metrics.length,4);
 assert.ok(p.rows.every(r=>r.title&&r.group&&r.state&&/^https:\/\/github\.com\/mvahora2023\//.test(r.source)));
});
test('dashboard is standalone and labels its scope',()=>{
 assert.match(html,/<!doctype html>/i);
 assert.match(html,/Source transparency/);
 assert.match(html,/static, locally runnable/i);
 assert.match(html,/Export filtered data/);
 assert.doesNotMatch(html,/<script[^>]+src=/i);
});
