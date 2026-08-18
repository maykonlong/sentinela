/**
 * Salvaguarda de cobertura do owasp-map.
 *
 * PROBLEMA QUE ESTE TESTE RESOLVE: `mapFinding()` tem um DEFAULT
 * ('Diversos / Boas práticas', CWE '—', confiança 'provável'). Quando uma regra
 * nova nasce em src/rules/ e ninguém lembra de mapeá-la, NADA quebra — o achado
 * simplesmente sai no relatório sem OWASP, sem CWE e rebaixado a 'provável',
 * mesmo sendo uma checagem determinística. O fallback esconde exatamente o que
 * precisaria ser visto.
 *
 * Este script varre o código-fonte procurando `type: '...'`, e FALHA (exit 1)
 * se algum type produzido pelas regras não estiver em MAP.
 *
 * Uso:  node test/owasp-map-coverage.mjs
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join, dirname, relative } from 'path';
import { fileURLToPath } from 'url';
import { findUnmappedTypes, listMappedTypes, NON_FINDING_TYPES } from '../src/rules/owasp-map.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Onde nascem achados. Varre recursivamente diretórios; arquivos avulsos entram
// pelo caminho direto. Deliberadamente NÃO varre src/report/ — lá os types são
// consumidos, não criados.
const SOURCES = ['src/rules', 'src/infra', 'src/auditor.mjs'];

function collectFiles(target) {
  const abs = join(ROOT, target);
  let st;
  try { st = statSync(abs); } catch { return []; }   // caminho some? não é erro deste teste
  if (st.isFile()) return [abs];
  return readdirSync(abs, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? collectFiles(join(target, e.name))
    : e.name.endsWith('.mjs') ? [join(abs, e.name)] : []
  );
}

const files = SOURCES.flatMap(collectFiles);
const seen = new Map();   // type -> Set de arquivos onde aparece

for (const file of files) {
  const src = readFileSync(file, 'utf8');
  // Casa `type: 'x'` e `type:'x'`, aspas simples ou duplas.
  for (const m of src.matchAll(/\btype:\s*['"]([a-z0-9_]+)['"]/g)) {
    const t = m[1];
    if (!seen.has(t)) seen.set(t, new Set());
    seen.get(t).add(relative(ROOT, file).replace(/\\/g, '/'));
  }
}

const observed = [...seen.keys()];
const unmapped = findUnmappedTypes(observed);
const ignored = observed.filter(t => NON_FINDING_TYPES.has(t));

console.log(`owasp-map coverage: ${files.length} arquivo(s), ${observed.length} type(s) observado(s), ${listMappedTypes().length} mapeado(s) no MAP.`);
if (ignored.length) console.log(`  ignorados (timeline/UI, não são achados): ${ignored.join(', ')}`);

if (unmapped.length) {
  console.error(`\n❌ FALHA: ${unmapped.length} type(s) sem mapeamento OWASP/CWE — cairiam no DEFAULT ('provável'):`);
  for (const t of unmapped) console.error(`   • ${t}   (em ${[...seen.get(t)].join(', ')})`);
  console.error('\nAdicione cada um em MAP (src/rules/owasp-map.mjs) ou, se for entrada de');
  console.error('timeline/UI e não um achado, em NON_FINDING_TYPES.');
  process.exit(1);
}

console.log('✅ OK: todo type produzido pelas regras tem OWASP/CWE/confiança explícitos.');
