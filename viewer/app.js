'use strict';
const $ = id => document.getElementById(id);
const state = {packages: [], id: null, dir: '', page: 0, next: null, file: null, offset: 0, data: null, generation: 0, listRequest: 0, readRequest: 0};
function status(text, error = false) { $('status').textContent = text; $('status').classList.toggle('error', error); }
// Archive names and contents must only enter the DOM through textContent.
function visible(text) { return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')); }
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $('theme-toggle').textContent = theme === 'light' ? 'Тёмная тема' : 'Светлая тема';
  $('theme-toggle').setAttribute('aria-pressed', String(theme === 'light'));
  $('theme-toggle').setAttribute('aria-label', theme === 'light' ? 'Включить тёмную тему' : 'Включить светлую тему');
}
let savedTheme;
try { savedTheme = localStorage.getItem('omcb-theme'); } catch (_) { /* Storage may be disabled. */ }
setTheme(savedTheme === 'light' || savedTheme === 'dark' ? savedTheme :
  (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
$('theme-toggle').addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  setTheme(theme);
  try { localStorage.setItem('omcb-theme', theme); } catch (_) { /* Session-only theme. */ }
});

// A small lexical highlighter, not a parser. Each byte chunk is independent.
// Only fixed CSS classes and text nodes are created; source is never HTML.
function highlightSource(text, path) {
  const fragment = document.createDocumentFragment();
  const python = /\.(py|pyi|pyw)$/i.test(path);
  const javascript = /\.(js|mjs|cjs|jsx)$/i.test(path);
  if (!python && !javascript) { fragment.append(document.createTextNode(text)); return fragment; }
  const keywords = new Set((python ?
    'False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case' :
    'async await break case catch class const continue debugger default delete do else export extends false finally for from function get if import in instanceof let new null of return set static super switch this throw true try typeof undefined var void while with yield').split(' '));
  const word = /[A-Za-z_$][A-Za-z0-9_$]*/y;
  const number = /(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?[\d_]+)?)[nj]?/y;
  let i = 0, plainStart = 0;
  function emit(end, kind) {
    if (plainStart < i) fragment.append(document.createTextNode(text.slice(plainStart, i)));
    const span = document.createElement('span'); span.className = 'tok-' + kind;
    span.textContent = text.slice(i, end); fragment.append(span);
    i = end; plainStart = i;
  }
  while (i < text.length) {
    if ((python && text[i] === '#') || (javascript && text.startsWith('//', i))) {
      const end = text.indexOf('\n', i); emit(end < 0 ? text.length : end, 'comment'); continue;
    }
    if (javascript && text.startsWith('/*', i)) {
      const end = text.indexOf('*/', i + 2); emit(end < 0 ? text.length : end + 2, 'comment'); continue;
    }
    if (text[i] === '"' || text[i] === "'" || (javascript && text[i] === '`')) {
      const quote = python && text.startsWith(text[i].repeat(3), i) ? text[i].repeat(3) : text[i];
      let end = i + quote.length;
      while (end < text.length) {
        if (text[end] === '\\') { end = Math.min(text.length, end + 2); continue; }
        if (text.startsWith(quote, end)) { end += quote.length; break; }
        if (quote.length === 1 && quote !== '`' && text[end] === '\n') break;
        end++;
      }
      emit(end, 'string'); continue;
    }
    word.lastIndex = i;
    const identifier = word.exec(text);
    if (identifier) {
      const end = word.lastIndex;
      if (keywords.has(identifier[0])) emit(end, 'keyword');
      else if (/^\s*\(/.test(text.slice(end))) emit(end, 'function');
      else i = end;
      continue;
    }
    number.lastIndex = i;
    if (number.test(text)) { emit(number.lastIndex, 'number'); continue; }
    i++;
  }
  if (plainStart < text.length) fragment.append(document.createTextNode(text.slice(plainStart)));
  return fragment;
}
async function api(route, params = {}) {
  const response = await fetch('/api/' + route + '?' + new URLSearchParams(params), {headers: {'X-Archive-Viewer': '1'}, cache: 'no-store'});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Ошибка чтения');
  return data;
}
function row(label, detail, action, selected = false, directory = false) {
  const button = document.createElement('button'); button.className = 'row' + (directory ? ' directory' : '');
  button.setAttribute('aria-current', String(selected));
  if (detail) { const small = document.createElement('small'); small.textContent = visible(detail); button.append(small); }
  const text = document.createElement('span'); text.textContent = visible(label); button.append(text);
  button.addEventListener('click', action); return button;
}
function empty(target, text) { const p = document.createElement('p'); p.className = 'empty'; p.textContent = text; target.replaceChildren(p); }
function benchmarkLabel(label) {
  const badge = document.createElement('span');
  const known = label === 'malicious' || label === 'benign';
  badge.className = 'benchmark-label' + (known ? ' label-' + label : '');
  badge.textContent = 'Бенчмарк: ' + (known ? label : 'неизвестно');
  badge.title = 'Разметка label_true из results/manifest.csv';
  return badge;
}
function packages() {
  const q = $('package-search').value.toLowerCase(), ecosystem = $('ecosystem').value;
  const selected = state.packages.filter(p => p.name.toLowerCase().includes(q) && (!ecosystem || p.ecosystem === ecosystem));
  $('package-count').textContent = selected.length + ' / ' + state.packages.length;
  $('package-list').replaceChildren(...selected.map(p => {
    const button = row(p.name, p.ecosystem.toUpperCase() + ' · #' + p.id, () => selectPackage(p), p.id === state.id);
    button.append(benchmarkLabel(p.label_true));
    return button;
  }));
  if (!selected.length) empty($('package-list'), 'Релизы не найдены');
}
function resetReader() {
  state.file = null; state.data = null; state.offset = 0; state.readRequest++;
  $('selected-file').textContent = 'Файл не выбран'; $('file-meta').textContent = 'Выберите файл в дереве архива';
  $('code').textContent = 'Выберите файл для просмотра.'; $('encoding').textContent = '';
  $('offset').value = 0; ['bytes-prev', 'bytes-next', 'offset', 'offset-go'].forEach(id => $(id).disabled = true);
}
function selectPackage(p) {
  state.id = p.id; state.dir = ''; state.page = 0; state.generation++;
  $('selected-package').textContent = visible(p.name);
  $('package-label').replaceChildren(benchmarkLabel(p.label_true));
  $('file-search').disabled = false; $('file-search').value = ''; resetReader(); packages(); listFiles();
}
function breadcrumbs() {
  $('breadcrumbs').replaceChildren();
  const segments = state.dir.split('/').filter(Boolean);
  const crumbs = [{label: 'Корень', path: ''}, ...segments.map((label, i) => ({label, path: segments.slice(0, i + 1).join('/')}))];
  for (const crumb of crumbs) {
    const button = document.createElement('button'); button.textContent = visible(crumb.label);
    button.addEventListener('click', () => {state.dir = crumb.path; state.page = 0; $('file-search').value = ''; listFiles();});
    $('breadcrumbs').append(button);
  }
}
async function listFiles() {
  if (!state.id) return;
  const request = ++state.listRequest, generation = state.generation;
  const query = $('file-search').value.trim();
  breadcrumbs(); $('files-prev').disabled = true; $('files-next').disabled = true;
  empty($('file-list'), 'Читаем структуру архива…'); status('Чтение архива…');
  try {
    const data = await api('list', {id: state.id, path: state.dir, page: state.page, q: query});
    if (request !== state.listRequest || generation !== state.generation) return;
    state.next = data.next_page;
    $('file-count').textContent = data.total;
    $('files-page').textContent = (state.page + 1) + ' / ' + Math.max(1, Math.ceil(data.total / 100));
    $('files-prev').disabled = state.page === 0; $('files-next').disabled = data.next_page === null;
    $('file-list').replaceChildren(...data.entries.map(e => row(query ? e.path : e.path.split('/').at(-1),
      e.type === 'directory' ? '▸ ПАПКА' : e.size.toLocaleString('ru-RU') + ' байт', event => {
        if (e.type === 'directory') {state.dir = e.path; state.page = 0; listFiles();}
        else {state.file = e.path; readFile(0); for (const b of $('file-list').children) b.setAttribute('aria-current', 'false'); event.currentTarget.setAttribute('aria-current', 'true');}
      }, state.file === e.path, e.type === 'directory')));
    if (!data.entries.length) empty($('file-list'), query ? 'Совпадений нет' : 'Папка пуста');
    status('Архив открыт. Символические ссылки скрыты.');
  } catch (e) {
    if (request !== state.listRequest || generation !== state.generation) return;
    empty($('file-list'), 'Не удалось открыть архив'); $('file-count').textContent = '—'; $('files-page').textContent = '—'; status(e.message, true);
  }
}
function renderCode() {
  if (!state.data) return;
  const d = state.data;
  if ($('hex').checked) {
    const bytes = d.base64 ? Uint8Array.from(atob(d.base64), c => c.charCodeAt(0)) : new TextEncoder().encode(d.text);
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const part = bytes.slice(i, i + 16);
      lines.push((d.offset + i).toString(16).padStart(8, '0') + '  ' + [...part].map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' + [...part].map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join(''));
    }
    $('code').textContent = lines.join('\n') || '(Пустой файл / конец файла)';
  } else {
    // Normalize line endings for display only; offsets and HEX use original bytes.
    const text = d.text.replace(/\r\n?/g, '\n');
    $('code').replaceChildren(highlightSource(visible(text) || '(Пустой файл / конец файла)', state.file));
  }
}
async function readFile(offset) {
  if (!state.file) return;
  const request = ++state.readRequest, generation = state.generation, file = state.file;
  state.data = null; $('code').textContent = 'Чтение…'; $('selected-file').textContent = visible(file);
  ['bytes-prev', 'bytes-next', 'offset', 'offset-go'].forEach(id => $(id).disabled = true);
  try {
    const data = await api('read', {id: state.id, path: file, offset});
    if (request !== state.readRequest || generation !== state.generation) return;
    state.data = data; state.offset = data.offset; $('offset').value = data.offset; $('offset').max = data.size;
    $('file-meta').textContent = `Байты ${data.offset}–${data.offset + data.bytes_read} (конец не включён) · всего ${data.size.toLocaleString('ru-RU')} байт`;
    $('encoding').textContent = data.base64 ? 'Не-UTF-8 / разрыв символа · точные байты в HEX' : 'UTF-8';
    $('bytes-prev').disabled = data.offset === 0; $('bytes-next').disabled = data.eof;
    $('offset').disabled = false; $('offset-go').disabled = false;
    renderCode(); $('code-container').scrollTop = 0; status('Файл открыт как текст. Управляющие и bidi-символы показаны как \\uXXXX.');
  } catch (e) {
    if (request !== state.readRequest || generation !== state.generation) return;
    $('code').textContent = 'Не удалось прочитать файл'; status(e.message, true);
  }
}
$('package-search').addEventListener('input', packages); $('ecosystem').addEventListener('change', packages);
let searchTimer;
$('file-search').addEventListener('input', () => {clearTimeout(searchTimer); state.listRequest++; searchTimer = setTimeout(() => {state.page = 0; listFiles();}, 250);});
$('files-prev').addEventListener('click', () => {state.page--; listFiles();});
$('files-next').addEventListener('click', () => {state.page = state.next; listFiles();});
$('bytes-prev').addEventListener('click', () => readFile(Math.max(0, state.offset - 16384)));
$('bytes-next').addEventListener('click', () => readFile(state.offset + state.data.bytes_read));
$('offset-form').addEventListener('submit', e => {e.preventDefault(); const offset = Number($('offset').value); if (Number.isSafeInteger(offset) && offset >= 0) readFile(offset);});
$('wrap').addEventListener('change', () => $('code').classList.toggle('wrap', $('wrap').checked));
$('hex').addEventListener('change', renderCode);
api('packages').then(data => {state.packages = data.packages; packages(); status('Выберите релиз для исследования.');}).catch(e => {empty($('package-list'), 'Не удалось загрузить релизы'); status(e.message, true);});
