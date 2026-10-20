const $ = id => document.getElementById(id);
let ME = null, CHUNK = 8 * 1024 * 1024;
async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!r.ok) {
    let m = r.statusText; try { m = (await r.json()).detail || m } catch (e) {}
    // Step-up auth: sensitive actions need a fresh code if the login is >15 min old.
    if (m === 'reauth_required' && ME && !opts._retried && !path.startsWith('/api/auth/')) {
      await fetch('/api/auth/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: ME.username }) });
      const code = prompt('Security check: this action needs a fresh login code.\nA code was emailed to you — enter it here:');
      if (!code) throw new Error('Cancelled');
      const rr = await fetch('/api/auth/reauth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code.trim() }) });
      if (!rr.ok) throw new Error('Re-authentication failed — code invalid or expired');
      return api(path, { ...opts, _retried: true });
    }
    throw new Error(m);
  }
  return r.status === 204 ? {} : r.json();
}
const fmtSize = b => b > 1e9 ? (b / 1e9).toFixed(2) + ' GB' : b > 1e6 ? (b / 1e6).toFixed(1) + ' MB' : b > 1e3 ? (b / 1e3).toFixed(1) + ' KB' : b + ' B';
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function show(view) { ['view-login', 'view-vault', 'view-admin'].forEach(v => $(v).classList.toggle('hidden', v !== view)); }

async function boot() {
  try { ME = await api('/api/me'); } catch (e) { ME = null; }
  if (!ME) { show('view-login'); $('who').textContent = ''; return; }
  $('who').innerHTML = `${esc(ME.display_name || ME.username)} (<b>${esc(ME.username)}</b>)`;
  $('tab-admin').classList.toggle('hidden', ME.role !== 'admin');
  show('view-vault'); loadVault();
}

$('btn-request').onclick = async () => {
  const username = $('login-username').value.trim(); if (!username) return;
  try {
    const r = await api('/api/auth/request', { method: 'POST', body: JSON.stringify({ username }) });
    $('login-msg').textContent = r.message;
    $('step-user').classList.add('hidden'); $('step-code').classList.remove('hidden');
  } catch (e) { $('login-msg').textContent = e.message; }
};
$('btn-back').onclick = () => { $('step-user').classList.remove('hidden'); $('step-code').classList.add('hidden'); };
$('btn-verify').onclick = async () => {
  try {
    await api('/api/auth/verify-code', { method: 'POST', body: JSON.stringify({ username: $('login-username').value.trim(), code: $('login-code').value.trim() }) });
    boot();
  } catch (e) { $('code-msg').textContent = e.message; }
};
async function logout() { try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) {} location.href = '/'; }
$('btn-logout').onclick = logout; $('btn-logout2').onclick = logout;
$('tab-admin').onclick = () => { show('view-admin'); loadAdmin(); };
$('tab-vault2').onclick = () => { show('view-vault'); loadVault(); };

let VAULT = { folders: [], files: [] };
async function loadVault() {
  VAULT = await api('/api/vault');
  const fsel = $('upload-folder');
  fsel.innerHTML = '<option value="">My root (no folder)</option>' + VAULT.folders.filter(f => f.perms && f.perms.upload).map(f => `<option value="${f.id}">${esc(f.name)} (${esc(f.owner)})</option>`).join('');
  $('folders').innerHTML = VAULT.folders.length ? `<table><tr><th>Name</th><th>Owner</th><th></th></tr>${VAULT.folders.map(f => `<tr><td>📁 ${esc(f.name)}</td><td>${esc(f.owner)}</td><td class="row"><button class="small ghost" onclick="shareRes('folder',${f.id})">Share</button>${f.perms.delete ? `<button class="small ghost" onclick="delFolder(${f.id})">Delete</button>` : ''}</td></tr>`).join('')}</table>` : '<p class="msg">No folders yet.</p>';
  const scanBadge = f => f.scan_status === 'clean' ? ' <span title="Virus scan: clean">✅</span>' : f.scan_status === 'infected' ? ' 🦠' : ' <span title="Virus scan: not scanned (scanner was unavailable)">❔</span>';
  const previewable = f => f.mime && (f.mime.startsWith('image/') || f.mime === 'application/pdf');
  $('files').innerHTML = VAULT.files.length ? `<table><tr><th>Name</th><th>Size</th><th>Owner</th><th>Uploaded</th><th></th></tr>${VAULT.files.map(f => `<tr><td>${esc(f.name)}${scanBadge(f)}</td><td>${fmtSize(f.size)}</td><td>${esc(f.owner)}</td><td>${new Date(f.created_at * 1000).toLocaleString()}</td><td class="row">${previewable(f) && f.perms.download ? `<a href="/api/files/${f.id}/preview" target="_blank"><button class="small ghost">Preview</button></a>` : ''}${f.perms.download ? `<a href="/api/files/${f.id}/download"><button class="small">Download</button></a>` : ''}<button class="small ghost" onclick="shareRes('file',${f.id})">Share</button>${f.perms.delete ? `<button class="small ghost" onclick="delFile(${f.id})">Delete</button>` : ''}</td></tr>`).join('')}</table>` : '<p class="msg">No files yet — upload something above.</p>';
  loadLinks(); loadTrash(); loadSessions(); loadSharing();
}
function fmtRemaining(l) {
  if (l.seconds_remaining === null || l.seconds_remaining === undefined) return 'never expires';
  if (l.seconds_remaining <= 0) return 'expired';
  const d = Math.floor(l.seconds_remaining / 86400), h = Math.floor((l.seconds_remaining % 86400) / 3600), m = Math.floor((l.seconds_remaining % 3600) / 60);
  if (d >= 1) return `${d} day${d === 1 ? '' : 's'} ${h}h left`;
  if (h >= 1) return `${h}h ${m}m left`;
  return `${m}m left`;
}
async function loadLinks() {
  try {
    const activeOnly = $('links-active-only') && $('links-active-only').checked;
    const links = await api('/api/links' + (activeOnly ? '?active_only=true' : ''));
    const statusTxt = l => l.status === 'active' ? '🟢 active' : l.status === 'expired' ? '⚪ expired' : l.status === 'exhausted' ? '🟠 used up' : '🔴 revoked';
    const canManage = l => ME && (ME.role === 'admin' || l.creator === ME.username);
    $('links').innerHTML = links.length ? `<table><tr><th>For</th><th>Created by</th><th>Used</th><th>Uses left</th><th>Time left</th><th>Expires</th><th>Status</th><th></th></tr>${links.map(l => `<tr><td>${esc(l.resource_type)}: ${esc(l.resource_name)}</td><td>${esc(l.creator)}</td><td>${l.downloads}${l.max_downloads ? ' of ' + l.max_downloads : ' (unlimited)'}</td><td>${l.uses_remaining === null ? '∞' : l.uses_remaining}</td><td>${fmtRemaining(l)}${l.days_remaining !== null && l.days_remaining !== undefined && l.seconds_remaining > 0 ? ` (${l.days_remaining} days)` : ''}</td><td>${l.expires_at ? new Date(l.expires_at * 1000).toLocaleString() : 'never'}</td><td>${statusTxt(l)}</td><td class="row">${canManage(l) ? `<button class="small ghost" onclick="regenLink(${l.id})">Regenerate</button>` : ''}${l.status === 'active' && canManage(l) ? `<button class="small ghost" onclick="revokeLink(${l.id})">Revoke</button>` : ''}</td></tr>`).join('')}</table>` : `<p class="msg">${activeOnly ? 'No active share links right now. Uncheck the box above to see expired/used-up links.' : 'No share links yet. Use Share → link on any file or folder.'}</p>`;
  } catch (e) { $('links').innerHTML = ''; }
}
window.regenLink = async id => {
  if (!confirm('Regenerate this link?\n\n• The old URL stops working immediately\n• A new URL is issued (shown once — copy it)\n• Download count resets to 0\n• Same download limit, and the full original time window restarts from now')) return;
  try {
    const r = await api(`/api/links/${id}/regenerate`, { method: 'POST' });
    prompt('New share link — copy it now (shown only once):', r.url);
  } catch (e) { alert(e.message); }
  loadLinks();
};
window.revokeLink = async id => { if (confirm('Revoke this share link? It will stop working immediately.')) { await api('/api/links/' + id, { method: 'DELETE' }); loadLinks(); } };
async function loadTrash() {
  try {
    const trash = await api('/api/trash');
    $('trash').innerHTML = trash.length ? `<table><tr><th>Name</th><th>Size</th><th>Deleted</th><th>Purges</th><th></th></tr>${trash.map(f => `<tr><td>${esc(f.name)}</td><td>${fmtSize(f.size)}</td><td>${new Date(f.deleted_at * 1000).toLocaleString()}</td><td>${new Date(f.purge_at * 1000).toLocaleDateString()}</td><td class="row"><button class="small" onclick="restoreFile(${f.id})">Restore</button><button class="small ghost" style="color:#ff9a8a" onclick="purgeFile(${f.id})">Purge forever</button></td></tr>`).join('')}</table>` : '<p class="msg">Trash is empty.</p>';
  } catch (e) { $('trash').innerHTML = ''; }
}
window.restoreFile = async id => { await api(`/api/files/${id}/restore`, { method: 'POST' }); loadVault(); };
window.purgeFile = async id => { if (confirm('Permanently purge this file? This cannot be undone.')) { await api(`/api/files/${id}/purge`, { method: 'DELETE' }); loadVault(); } };
async function loadSessions() {
  try {
    const ss = await api('/api/me/sessions');
    $('sessions').innerHTML = ss.length ? `<table><tr><th>Logged in</th><th>IP</th><th>Device</th><th>Expires</th><th></th></tr>${ss.map(s => `<tr><td>${new Date(s.created_at * 1000).toLocaleString()}</td><td>${esc(s.ip)}</td><td>${esc((s.ua || '').slice(0, 60))}</td><td>${new Date(s.expires_at * 1000).toLocaleString()}</td><td>${s.current ? '<b>this device</b>' : `<button class="small ghost" onclick="revokeSession(${s.id})">Revoke</button>`}</td></tr>`).join('')}</table>` : '<p class="msg">No sessions.</p>';
  } catch (e) { $('sessions').innerHTML = ''; }
}
window.revokeSession = async id => { await api('/api/me/sessions/' + id, { method: 'DELETE' }); loadSessions(); };
$('btn-revoke-others').onclick = async () => { await api('/api/me/sessions/revoke-others', { method: 'POST' }); loadSessions(); alert('Other sessions revoked'); };
if ($('links-active-only')) $('links-active-only').onchange = loadLinks;
window.delFile = async id => { if (confirm('Delete this file?')) { await api('/api/files/' + id, { method: 'DELETE' }); loadVault(); } };
window.delFolder = async id => { if (confirm('Delete this folder? (files inside are not deleted)')) { await api('/api/folders/' + id, { method: 'DELETE' }); loadVault(); } };
window.shareRes = async (type, id) => {
  const target = prompt('Share with:\n• a username (e.g. bob)\n• a group:  group:GROUPNAME\n• anyone with a link:  link');
  if (!target) return;
  const t = target.trim();
  if (t.toLowerCase() === 'link') {
    if (ME && !ME.can_share_link) { alert('Share links are not enabled for your account — ask the vault admin to enable them.'); return; }
    const days = prompt('Link expires in how many days?', '7'); if (days === null) return;
    const maxdl = prompt('Max downloads (0 = unlimited)?', '0'); if (maxdl === null) return;
    try {
      const r = await api(`/api/${type === 'file' ? 'files' : 'folders'}/${id}/link`, { method: 'POST', body: JSON.stringify({ expires_days: parseInt(days) || 7, max_downloads: parseInt(maxdl) || 0 }) });
      prompt('Share link created — copy it now (it is shown only once):', r.url);
    } catch (e) { alert(e.message); }
    loadVault(); return;
  }
  const upload = type === 'folder' && confirm('Also allow UPLOAD into this folder? OK = yes, Cancel = download only');
  const body = t.toLowerCase().startsWith('group:')
    ? { group: t.slice(6).trim(), can_download: true, can_upload: upload }
    : { username: t, can_download: true, can_upload: upload };
  try {
    await api(`/api/${type === 'file' ? 'files' : 'folders'}/${id}/share`, { method: 'POST', body: JSON.stringify(body) });
    alert('Shared with ' + t);
  } catch (e) { alert(e.message); }
  loadVault();
};
$('btn-folder').onclick = async () => {
  const name = $('new-folder-name').value.trim(); if (!name) return;
  await api('/api/folders', { method: 'POST', body: JSON.stringify({ name }) });
  $('new-folder-name').value = ''; loadVault();
};

// ---- chunked, resumable upload ----
async function uploadFile(file) {
  const folder_id = $('upload-folder').value ? parseInt($('upload-folder').value) : null;
  const init = await api('/api/uploads/init', { method: 'POST', body: JSON.stringify({ filename: file.name, size: file.size, folder_id, mime: file.type || '' }) });
  CHUNK = init.chunk_size;
  let st = { received: [] };
  try { st = await api(`/api/uploads/${init.upload_id}/status`); } catch (e) {}
  const done = new Set(st.received || []);
  const prog = $('up-progress'); prog.classList.remove('hidden');
  for (let i = 0; i < init.total_chunks; i++) {
    if (done.has(i)) continue;
    const blob = file.slice(i * CHUNK, Math.min(file.size, (i + 1) * CHUNK));
    const r = await fetch(`/api/uploads/${init.upload_id}/chunk/${i}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: blob });
    if (!r.ok) throw new Error('Chunk ' + i + ' failed');
    prog.value = Math.round(((i + 1) / init.total_chunks) * 100);
    $('up-msg').textContent = `${file.name}: ${prog.value}%`;
  }
  await api(`/api/uploads/${init.upload_id}/complete`, { method: 'POST' });
  $('up-msg').textContent = `${file.name}: done ✔`;
}
async function handleFiles(files) {
  for (const f of files) { try { await uploadFile(f); } catch (e) { $('up-msg').textContent = f.name + ': ' + e.message; } }
  loadVault();
}
const drop = $('drop');
drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
drop.ondragleave = () => drop.classList.remove('over');
drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); handleFiles(e.dataTransfer.files); };
$('file-input').onchange = e => handleFiles(e.target.files);

async function loadSharing() {
  const el = $('sharing'); if (!el) return;
  try {
    const d = await api('/api/sharing');
    const perms = s => [s.can_download ? 'download' : '', s.can_upload ? 'upload' : '', s.can_delete ? 'delete' : ''].filter(Boolean).join(', ') || 'view';
    el.innerHTML =
      `<h3 style="margin:10px 0 4px">Shared by me</h3>` + (d.by_me.length ? `<table><tr><th>Item</th><th>Shared with</th><th>Permissions</th><th>Expires</th><th></th></tr>${d.by_me.map(s => `<tr><td>${s.resource_type === 'folder' ? '📁' : '📄'} ${esc(s.resource_name)}</td><td>${s.kind === 'group' ? '👥 ' : ''}${esc(s.target)}</td><td>${perms(s)}</td><td>${s.expires_at ? new Date(s.expires_at * 1000).toLocaleDateString() : 'never'}</td><td><button class="small ghost" onclick="revokeShare(${s.id},'${s.kind}')">Revoke</button></td></tr>`).join('')}</table>` : '<p class="msg">You have not shared anything yet.</p>') +
      `<h3 style="margin:14px 0 4px">Shared with me</h3>` + (d.with_me.length ? `<table><tr><th>Item</th><th>Owner</th><th>Via</th><th>Permissions</th></tr>${d.with_me.map(s => `<tr><td>${s.resource_type === 'folder' ? '📁' : '📄'} ${esc(s.resource_name)}</td><td>${esc(s.owner)}</td><td>${esc(s.via)}</td><td>${perms(s)}</td></tr>`).join('')}</table>` : '<p class="msg">Nothing has been shared with you yet.</p>');
  } catch (e) { el.innerHTML = ''; }
}
window.revokeShare = async (id, kind) => { if (confirm('Revoke this share?')) { await api(`/api/shares/${id}?kind=${kind}`, { method: 'DELETE' }); loadSharing(); if (typeof loadAdminFiles === 'function') loadAdminFiles(); if (typeof loadAdminShares === 'function') loadAdminShares(); } };

// ---- admin ----
let ADMIN_USERS = [];
function fileInfo(u) { return u.file_count ? `${u.file_count} file${u.file_count === 1 ? '' : 's'} (${fmtSize(u.files_bytes)})` : 'no files'; }
async function loadAdmin() {
  const stats = await api('/api/admin/stats');
  $('stats').textContent = `${stats.users} users · ${stats.files} files (${fmtSize(stats.files_bytes)}) · disk free ${fmtSize(stats.disk_free)} of ${fmtSize(stats.disk_total)}`;
  const users = await api('/api/admin/users');
  ADMIN_USERS = users;
  $('edit-user').classList.add('hidden');
  $('users').innerHTML = `<table><tr><th>Username</th><th>Email</th><th>Name</th><th>Role</th><th>Active</th><th>Share links</th><th>Files</th><th></th></tr>${users.map(u => `<tr><td>${esc(u.username)}</td><td>${esc(u.email)}</td><td>${esc(u.display_name)}</td><td>${esc(u.role)}</td><td>${u.active ? 'yes' : 'NO'}</td><td>${u.role === 'admin' ? 'always' : (u.can_share_link ? '✔ allowed' : '—')}</td><td>${fileInfo(u)}</td><td class="row"><button class="small" onclick="editUser(${u.id})">Edit</button>${ME && u.username !== ME.username ? `<button class="small ghost" onclick="toggleUser(${u.id},${u.active})">${u.active ? 'Disable' : 'Enable'}</button><button class="small ghost" onclick="revokeUser(${u.id})">Revoke sessions</button><button class="small ghost" onclick="deleteUser(${u.id})" style="color:#ff9a8a">Delete</button>` : '<span class="msg">you</span>'}</td></tr>`).join('')}</table>`;
  loadGroups();
  const s = await api('/api/admin/settings');
  $('settings').innerHTML = Object.entries(s).map(([k, v]) => `<label>${esc(k)}</label><input data-setting="${esc(k)}" value="${esc(v)}">`).join('');
  loadAdminFiles(); loadAdminShares();
  const audit = await api('/api/admin/audit?limit=100');
  $('audit').innerHTML = `<table><tr><th>When</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr>${audit.map(a => `<tr><td>${new Date(a.ts * 1000).toLocaleString()}</td><td>${esc(a.username)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td><td>${esc(a.ip)}</td></tr>`).join('')}</table>`;
}
async function loadAdminFiles() {
  const el = $('admin-files'); if (!el) return;
  const owner = $('af-owner') ? $('af-owner').value : '', q = $('af-q') ? $('af-q').value.trim() : '';
  try {
    const d = await api(`/api/admin/files?owner=${encodeURIComponent(owner)}&q=${encodeURIComponent(q)}`);
    const sel = $('af-owner');
    if (sel && sel.options.length <= 1) { for (const u of ADMIN_USERS) sel.innerHTML += `<option value="${esc(u.username)}">${esc(u.username)}</option>`; }
    el.innerHTML = d.files.length ? `<table><tr><th>File</th><th>Owner</th><th>Size</th><th>Folder</th><th>Scan</th><th>Shares</th><th>Uploaded</th><th></th></tr>${d.files.map(f => `<tr><td>📄 ${esc(f.name)}</td><td>${esc(f.owner)}</td><td>${fmtSize(f.size)}</td><td>${esc(f.folder_name || '—')}</td><td>${esc(f.scan_status)}</td><td>${f.user_shares + f.group_shares ? `${f.user_shares} user · ${f.group_shares} group` : '—'}${f.links ? ` · ${f.links} link${f.links === 1 ? '' : 's'}` : ''}</td><td>${new Date(f.created_at * 1000).toLocaleString()}</td><td><button class="small ghost" style="color:#ff9a8a" onclick="adminTrashFile(${f.id})">Move to owner's trash</button></td></tr>`).join('')}</table>` : '<p class="msg">No files match.</p>';
    $('admin-folders').innerHTML = d.folders.length ? `<h3 style="margin:12px 0 4px">Folders</h3><table><tr><th>Folder</th><th>Owner</th><th>Shares</th><th></th></tr>${d.folders.map(f => `<tr><td>📁 ${esc(f.name)}</td><td>${esc(f.owner)}</td><td>${f.user_shares + f.group_shares ? `${f.user_shares} user · ${f.group_shares} group` : '—'}</td><td><button class="small ghost" style="color:#ff9a8a" onclick="adminTrashFolder(${f.id})">Move to owner's trash</button></td></tr>`).join('')}</table>` : '';
  } catch (e) { el.innerHTML = ''; }
}
window.adminTrashFile = async id => { if (confirm("Move this file to its owner's trash? The owner can restore it until the trash retention passes.")) { await api('/api/admin/files/' + id, { method: 'DELETE' }); loadAdminFiles(); } };
window.adminTrashFolder = async id => { if (confirm("Move this folder to its owner's trash?")) { await api('/api/admin/folders/' + id, { method: 'DELETE' }); loadAdminFiles(); } };
if ($('btn-affilter')) $('btn-affilter').onclick = loadAdminFiles;
async function loadAdminShares() {
  const el = $('admin-shares'); if (!el) return;
  try {
    const rows = await api('/api/admin/shares');
    const perms = s => [s.can_download ? 'download' : '', s.can_upload ? 'upload' : '', s.can_delete ? 'delete' : ''].filter(Boolean).join(', ') || 'view';
    el.innerHTML = rows.length ? `<table><tr><th>Item</th><th>Owner</th><th>Shared with</th><th>Permissions</th><th>Granted by</th><th>Expires</th><th></th></tr>${rows.map(s => `<tr><td>${s.resource_type === 'folder' ? '📁' : '📄'} ${esc(s.resource_name)}</td><td>${esc(s.owner)}</td><td>${s.kind === 'group' ? '👥 group: ' : ''}${esc(s.target)}</td><td>${perms(s)}</td><td>${esc(s.granted_by)}</td><td>${s.expires_at ? new Date(s.expires_at * 1000).toLocaleDateString() : 'never'}</td><td><button class="small ghost" onclick="revokeShare(${s.id},'${s.kind}')">Revoke</button></td></tr>`).join('')}</table>` : '<p class="msg">No shares exist yet.</p>';
  } catch (e) { el.innerHTML = ''; }
}
let EDIT_ID = null;
window.editUser = id => {
  const u = ADMIN_USERS.find(x => x.id === id); if (!u) return;
  EDIT_ID = id;
  $('e-username').textContent = u.username;
  $('e-email').value = u.email; $('e-name').value = u.display_name || '';
  $('e-role').value = u.role; $('e-active').checked = !!u.active; $('e-linkperm').checked = !!u.can_share_link;
  $('e-quota').value = u.quota_bytes ? Math.round(u.quota_bytes / 1e9) : '';
  $('edit-msg').textContent = '';
  $('edit-user').classList.remove('hidden');
  $('edit-user').scrollIntoView({ behavior: 'smooth', block: 'center' });
};
$('btn-canceledit').onclick = () => { $('edit-user').classList.add('hidden'); EDIT_ID = null; };
$('btn-saveuser').onclick = async () => {
  if (!EDIT_ID) return;
  const quota = $('e-quota').value.trim();
  try {
    await api('/api/admin/users/' + EDIT_ID, { method: 'PATCH', body: JSON.stringify({
      email: $('e-email').value.trim(), display_name: $('e-name').value.trim(),
      role: $('e-role').value, active: $('e-active').checked ? 1 : 0,
      can_share_link: $('e-linkperm').checked ? 1 : 0,
      quota_bytes: quota === '' ? null : Math.round(parseFloat(quota) * 1e9) }) });
    $('admin-msg').textContent = 'User updated ✔'; loadAdmin();
  } catch (e) { $('edit-msg').textContent = e.message; }
};
window.deleteUser = async id => {
  const u = ADMIN_USERS.find(x => x.id === id); if (!u) return;
  let mode = 'transfer';
  if (u.file_count > 0) {
    const delFiles = confirm(`${u.username} owns ${fileInfo(u)}.\n\nOK = DELETE their files permanently\nCancel = keep files and transfer ownership to you`);
    mode = delFiles ? 'delete' : 'transfer';
  }
  if (!confirm(`Permanently delete user "${u.username}"?${u.file_count > 0 ? `\nTheir files will be ${mode === 'delete' ? 'DELETED FOREVER' : 'transferred to you'}.` : ''}\n\nThis cannot be undone.`)) return;
  try {
    await api(`/api/admin/users/${id}?owned_files=${mode}`, { method: 'DELETE' });
    $('admin-msg').textContent = `User ${u.username} deleted ✔`; loadAdmin();
  } catch (e) { $('admin-msg').textContent = e.message; }
};
window.toggleUser = async (id, active) => { await api('/api/admin/users/' + id, { method: 'PATCH', body: JSON.stringify({ active: active ? 0 : 1 }) }); loadAdmin(); };
window.revokeUser = async id => { await api(`/api/admin/users/${id}/revoke-sessions`, { method: 'POST' }); alert('Sessions revoked'); };
$('btn-adduser').onclick = async () => {
  try {
    await api('/api/admin/users', { method: 'POST', body: JSON.stringify({ username: $('u-username').value, email: $('u-email').value, display_name: $('u-name').value, role: $('u-role').value, can_share_link: $('u-linkperm').checked }) });
    $('admin-msg').textContent = 'User added ✔'; loadAdmin();
  } catch (e) { $('admin-msg').textContent = e.message; }
};
let ADMIN_GROUPS = [];
async function loadGroups() {
  try {
    ADMIN_GROUPS = await api('/api/admin/groups');
    $('groups').innerHTML = ADMIN_GROUPS.length ? ADMIN_GROUPS.map(g => `<div class="row" style="margin:6px 0"><b>${esc(g.name)}</b><span class="msg">${g.members.length ? g.members.map(esc).join(', ') : 'no members'}</span><button class="small ghost" onclick="groupAddMember(${g.id})">Add member</button><button class="small ghost" onclick="groupRemoveMember(${g.id})">Remove member</button><button class="small ghost" style="color:#ff9a8a" onclick="groupDelete(${g.id})">Delete group</button></div>`).join('') : '<p class="msg">No groups yet. Create one, add members, then share with group:NAME.</p>';
  } catch (e) { $('groups').innerHTML = ''; }
}
$('btn-addgroup').onclick = async () => {
  const name = $('g-name').value.trim(); if (!name) return;
  try { await api('/api/admin/groups', { method: 'POST', body: JSON.stringify({ name }) }); $('g-name').value = ''; loadGroups(); $('admin-msg').textContent = 'Group created ✔'; }
  catch (e) { $('admin-msg').textContent = e.message; }
};
window.groupAddMember = async gid => {
  const username = prompt('Add which username to this group?'); if (!username) return;
  try { await api(`/api/admin/groups/${gid}/members`, { method: 'POST', body: JSON.stringify({ username }) }); } catch (e) { alert(e.message); }
  loadGroups();
};
window.groupRemoveMember = async gid => {
  const g = ADMIN_GROUPS.find(x => x.id === gid); if (!g) return;
  const username = prompt('Remove which member?\nMembers: ' + g.members.join(', ')); if (!username) return;
  const users = await api('/api/admin/users');
  const u = users.find(x => x.username === username.trim().toLowerCase());
  if (!u) { alert('No such user'); return; }
  await api(`/api/admin/groups/${gid}/members/${u.id}`, { method: 'DELETE' }); loadGroups();
};
window.groupDelete = async gid => { if (confirm('Delete this group? Group shares made to it will also be removed.')) { await api('/api/admin/groups/' + gid, { method: 'DELETE' }); loadGroups(); } };
$('btn-settings').onclick = async () => {
  const body = {}; document.querySelectorAll('[data-setting]').forEach(i => body[i.dataset.setting] = i.value);
  await api('/api/admin/settings', { method: 'PUT', body: JSON.stringify(body) }); alert('Settings saved');
};

boot();
