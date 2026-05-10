// ============================================================
// QA SYSTEM — GOOGLE APPS SCRIPT BACKEND v3
// Speed + Auth edition
// ============================================================
var FOLDER_ID       = '1lf63ycye1UjzX7D4ZONNSHdFnVLp-h1h';
var MASTER_SHEET_ID = '1cjAGAl6reeDDFbv8cWK7L1_FeljZmm5uQEPFcFV9jLA';

// ── Session tokens expire after 8 hours ──
var SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function doGet(e) {
  var action  = e.parameter.action  || '';
  var project = (e.parameter.project || '').trim();
  var token   = (e.parameter.token  || '').trim();
  try {
    // Public endpoints (no auth needed)
    if (action === 'ping') return out({ ok: true, ts: Date.now() });

    // Auth endpoints
    if (action === 'checkToken') return out(checkToken(token));

    // Protected endpoints
    var user = requireAuth(token);
    if (user.error) return out(user);

    var result;
    if      (action === 'listProjects') result = listProjects();
    else if (action === 'getProject')   result = getProject(project);
    else if (action === 'getMaster')    result = getMasterChecklist();
    else if (action === 'getInit')      result = getInit(project);  // combined master+project in one call
    else result = { error: 'Unknown action: ' + action };
    return out(result);
  } catch(err) { return out({ error: err.message }); }
}

function doPost(e) {
  try {
    var body   = JSON.parse(e.postData.contents);
    var action = body.action || '';
    var token  = body.token  || '';

    // Auth endpoints (no token needed)
    if (action === 'register') return out(register(body.name, body.email, body.password));
    if (action === 'login')    return out(login(body.email, body.password));
    if (action === 'logout')   return out(logout(token));

    // Protected endpoints
    var user = requireAuth(token);
    if (user.error) return out(user);

    var result;
    if      (action === 'createProject') result = createProject(body.project);
    else if (action === 'saveAllState')  result = saveAllState(body.project, body.state);
    else if (action === 'logActivity')   result = logActivity(body.project, body.entry);
    else result = { error: 'Unknown action' };
    return out(result);
  } catch(err) { return out({ error: err.message }); }
}

function out(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ════════════════════════════════════════
// AUTH SYSTEM
// ════════════════════════════════════════

function getUsersSheet() {
  var folder = DriveApp.getFolderById(FOLDER_ID);
  var files  = folder.getFilesByName('QA Auth');
  var ss, sh;
  if (files.hasNext()) {
    ss = SpreadsheetApp.open(files.next());
    sh = ss.getSheetByName('Users');
    if (!sh) {
      sh = ss.insertSheet('Users');
      sh.appendRow(['Email','Name','PasswordHash','Role','CreatedAt','LastLogin','Token','TokenExpiry','Active']);
      sh.setFrozenRows(1);
    }
    return sh;
  }
  ss = SpreadsheetApp.create('QA Auth');
  DriveApp.getFileById(ss.getId()).moveTo(folder);
  sh = ss.getActiveSheet().setName('Users');
  sh.appendRow(['Email','Name','PasswordHash','Role','CreatedAt','LastLogin','Token','TokenExpiry','Active']);
  sh.setFrozenRows(1);
  return sh;
}

function hashPassword(password) {
  // Simple deterministic hash — sufficient for internal tool
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,
    password + 'qa_salt_2026',
    Utilities.Charset.UTF_8);
  return bytes.map(function(b) {
    return ('0' + (b & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function generateToken() {
  return Utilities.getUuid().replace(/-/g,'') + Utilities.getUuid().replace(/-/g,'');
}

function register(name, email, password) {
  if (!name || !email || !password) return { error: 'Name, email and password are required' };
  email = email.toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: 'Invalid email address' };
  if (password.length < 6) return { error: 'Password must be at least 6 characters' };

  var sh   = getUsersSheet();
  var data = sh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).toLowerCase() === email) return { error: 'Email already registered' };
  }

  var token   = generateToken();
  var expiry  = Date.now() + SESSION_TTL_MS;
  var isFirst = data.length <= 1; // first user gets admin role
  sh.appendRow([
    email, name, hashPassword(password),
    isFirst ? 'admin' : 'member',
    new Date().toISOString(), new Date().toISOString(),
    token, expiry, 'true'
  ]);
  return { ok: true, token: token, name: name, email: email, role: isFirst ? 'admin' : 'member' };
}

function login(email, password) {
  if (!email || !password) return { error: 'Email and password are required' };
  email = email.toLowerCase().trim();

  var sh   = getUsersSheet();
  var data = sh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).toLowerCase() !== email) continue;
    if (String(data[i][8]).toLowerCase() === 'false') return { error: 'Account is deactivated' };
    if (data[i][2] !== hashPassword(password)) return { error: 'Incorrect password' };
    // Issue new token
    var token  = generateToken();
    var expiry = Date.now() + SESSION_TTL_MS;
    sh.getRange(i + 1, 7, 1, 3).setValues([[token, expiry, 'true']]);
    sh.getRange(i + 1, 6).setValue(new Date().toISOString());
    return { ok: true, token: token, name: String(data[i][1]), email: email, role: String(data[i][3]) };
  }
  return { error: 'Email not found' };
}

function logout(token) {
  if (!token) return { ok: true };
  var sh   = getUsersSheet();
  var data = sh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][6] === token) {
      sh.getRange(i + 1, 7).setValue('');
      return { ok: true };
    }
  }
  return { ok: true };
}

function checkToken(token) {
  if (!token) return { valid: false };
  var sh   = getUsersSheet();
  var data = sh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][6] !== token) continue;
    if (Date.now() > Number(data[i][7])) return { valid: false, reason: 'expired' };
    // Refresh token TTL on use
    sh.getRange(i + 1, 8).setValue(Date.now() + SESSION_TTL_MS);
    return { valid: true, name: String(data[i][1]), email: String(data[i][0]), role: String(data[i][3]) };
  }
  return { valid: false };
}

function requireAuth(token) {
  var check = checkToken(token);
  if (!check.valid) return { error: 'auth_required', reason: check.reason || 'invalid' };
  return check; // returns { valid, name, email, role }
}

// ════════════════════════════════════════
// SPEED: Combined init call (master + project state in ONE request)
// ════════════════════════════════════════

function getInit(projectName) {
  var master  = getMasterChecklist();
  var project = projectName ? getProject(projectName) : { found: false };
  var list    = listProjects();
  return { master: master, project: project, projects: list.projects };
}

// ════════════════════════════════════════
// REGISTRY
// ════════════════════════════════════════

function getRegistrySheet() {
  var folder = DriveApp.getFolderById(FOLDER_ID);
  var files  = folder.getFilesByName('QA Projects Registry');
  if (files.hasNext()) {
    var ss = SpreadsheetApp.open(files.next());
    var sh = ss.getSheetByName('Projects');
    if (!sh) {
      sh = ss.insertSheet('Projects');
      sh.appendRow(['ProjectName','SheetId','Created','LastUpdated']);
      sh.setFrozenRows(1);
    }
    return sh;
  }
  var ss = SpreadsheetApp.create('QA Projects Registry');
  DriveApp.getFileById(ss.getId()).moveTo(folder);
  var sh = ss.getActiveSheet().setName('Projects');
  sh.appendRow(['ProjectName','SheetId','Created','LastUpdated']);
  sh.setFrozenRows(1);
  return sh;
}

function listProjects() {
  var sh   = getRegistrySheet();
  var data = sh.getDataRange().getValues();
  var out  = [];
  for (var i = 1; i < data.length; i++) {
    if (data[i][0]) out.push({
      name: data[i][0], sheetId: data[i][1],
      created: String(data[i][2]), lastUpdated: String(data[i][3])
    });
  }
  return { projects: out };
}

function getProject(projectName) {
  if (!projectName) return { error: 'No project name' };
  var sh   = getRegistrySheet();
  var data = sh.getDataRange().getValues();
  var sheetId = null;
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === projectName) { sheetId = data[i][1]; break; }
  }
  if (!sheetId) return { found: false };
  var pss     = SpreadsheetApp.openById(sheetId);
  var stateSh = pss.getSheetByName('State');
  var actSh   = pss.getSheetByName('Activity');
  var state   = {};
  if (stateSh && stateSh.getLastRow() > 1) {
    var sd = stateSh.getDataRange().getValues();
    for (var r = 1; r < sd.length; r++) {
      if (sd[r][0]) { try { state[sd[r][0]] = JSON.parse(sd[r][1]); } catch(e) {} }
    }
  }
  var activity = [];
  if (actSh && actSh.getLastRow() > 1) {
    var ad = actSh.getDataRange().getValues();
    for (var r = 1; r < ad.length; r++) {
      if (ad[r][0]) activity.push({ msg: ad[r][0], type: ad[r][1], ts: ad[r][2] });
    }
  }
  return { found: true, projectName: projectName, state: state, activity: activity.slice(0,50) };
}

function createProject(projectName) {
  if (!projectName) return { error: 'No project name' };
  var regSh = getRegistrySheet();
  var data  = regSh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === projectName) return { created: false, sheetId: data[i][1], alreadyExists: true };
  }
  var folder = DriveApp.getFolderById(FOLDER_ID);
  var pss    = SpreadsheetApp.create('QA \u2014 ' + projectName);
  DriveApp.getFileById(pss.getId()).moveTo(folder);
  var infoSh = pss.getActiveSheet().setName('Info');
  infoSh.appendRow(['Project', projectName]);
  infoSh.appendRow(['Created', new Date().toISOString()]);
  var stateSh = pss.insertSheet('State');
  stateSh.appendRow(['Key','Value']); stateSh.setFrozenRows(1);
  var actSh = pss.insertSheet('Activity');
  actSh.appendRow(['Message','Type','Timestamp']); actSh.setFrozenRows(1);
  regSh.appendRow([projectName, pss.getId(), new Date().toISOString(), new Date().toISOString()]);
  return { created: true, sheetId: pss.getId(), sheetUrl: 'https://docs.google.com/spreadsheets/d/' + pss.getId() };
}

function saveAllState(projectName, stateObj) {
  if (!projectName) return { error: 'No project' };
  var regSh = getRegistrySheet();
  var data  = regSh.getDataRange().getValues();
  var sheetId = null; var regRow = -1;
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === projectName) { sheetId = data[i][1]; regRow = i + 1; break; }
  }
  if (!sheetId) { var c = createProject(projectName); sheetId = c.sheetId; }
  var pss     = SpreadsheetApp.openById(sheetId);
  var stateSh = pss.getSheetByName('State');
  stateSh.clearContents();
  stateSh.appendRow(['Key','Value']);
  var keys = Object.keys(stateObj || {});
  if (keys.length > 0) {
    var rows = keys.map(function(k) { return [k, JSON.stringify(stateObj[k])]; });
    stateSh.getRange(2, 1, rows.length, 2).setValues(rows);
  }
  if (regRow > 0) regSh.getRange(regRow, 4).setValue(new Date().toISOString());
  return { ok: true };
}

function logActivity(projectName, entry) {
  if (!projectName || !entry) return { error: 'Missing params' };
  var regSh = getRegistrySheet();
  var data  = regSh.getDataRange().getValues();
  var sheetId = null;
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === projectName) { sheetId = data[i][1]; break; }
  }
  if (!sheetId) return { error: 'Project not found' };
  var actSh = SpreadsheetApp.openById(sheetId).getSheetByName('Activity');
  actSh.insertRowAfter(1);
  actSh.getRange(2,1,1,3).setValues([[entry.msg, entry.type, entry.ts]]);
  if (actSh.getLastRow() > 52) actSh.deleteRow(actSh.getLastRow());
  return { ok: true };
}

function getMasterChecklist() {
  var sh   = SpreadsheetApp.openById(MASTER_SHEET_ID).getSheets()[0];
  var data = sh.getDataRange().getValues();
  var csv  = data.map(function(row) {
    return row.map(function(c) {
      var s = String(c);
      return (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0)
        ? '"' + s.replace(/"/g,'""') + '"' : s;
    }).join(',');
  }).join('\n');
  return { csv: csv };
}
