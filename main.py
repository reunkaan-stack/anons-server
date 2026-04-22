"""
Anons Lisans Sunucusu
FastAPI + SQLite
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3, secrets, string, hashlib, os

app = FastAPI()

DB = "licenses.db"
TRIAL_DAYS = 7
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "degistir-bunu-gizli-tut")

# ── Veritabanı ─────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS trials (
            mac         TEXT PRIMARY KEY,
            first_seen  TEXT NOT NULL,
            blocked     INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS licenses (
            key         TEXT PRIMARY KEY,
            mac         TEXT,
            activated_at TEXT,
            expires_at  TEXT,
            plan        TEXT DEFAULT 'lifetime',
            active      INTEGER DEFAULT 1,
            note        TEXT,
            created_at  TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ── Yardımcılar ────────────────────────────────────────────────────────────

def generate_key():
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(5)) for _ in range(4)]
    return '-'.join(parts)

def hash_mac(mac: str) -> str:
    return hashlib.sha256(mac.lower().strip().encode()).hexdigest()

def check_admin(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Yetkisiz erişim")

# ── Modeller ───────────────────────────────────────────────────────────────

class TrialRequest(BaseModel):
    mac: str

class ActivateRequest(BaseModel):
    key: str
    mac: str

class CreateKeyRequest(BaseModel):
    plan: str = "lifetime"
    note: str = ""
    count: int = 1

class RevokeRequest(BaseModel):
    key: str

# ── İstemci Endpointleri ───────────────────────────────────────────────────

@app.post("/trial/check")
def trial_check(req: TrialRequest):
    """Trial durumunu kontrol et veya kaydet."""
    mac_hash = hash_mac(req.mac)
    conn = get_db()

    row = conn.execute("SELECT * FROM trials WHERE mac=?", (mac_hash,)).fetchone()

    if row is None:
        # İlk kez görüyoruz
        conn.execute(
            "INSERT INTO trials (mac, first_seen) VALUES (?, ?)",
            (mac_hash, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        return {"status": "trial", "days_left": TRIAL_DAYS, "message": "Trial başladı"}

    if row["blocked"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Bu cihaz engellendi")

    first_seen = datetime.fromisoformat(row["first_seen"])
    days_passed = (datetime.utcnow() - first_seen).days
    days_left = max(0, TRIAL_DAYS - days_passed)

    conn.close()

    if days_left > 0:
        return {"status": "trial", "days_left": days_left, "message": f"Trial: {days_left} gün kaldı"}
    else:
        raise HTTPException(status_code=402, detail="Trial süresi doldu. Lisans satın alın.")


@app.post("/license/activate")
def activate_license(req: ActivateRequest):
    """Key'i aktive et ve MAC'e bağla."""
    mac_hash = hash_mac(req.mac)
    conn = get_db()

    row = conn.execute("SELECT * FROM licenses WHERE key=?", (req.key.upper(),)).fetchone()

    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Geçersiz lisans anahtarı")

    if not row["active"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Bu lisans iptal edilmiş")

    if row["mac"] and row["mac"] != mac_hash:
        conn.close()
        raise HTTPException(status_code=409, detail="Bu key başka bir cihaza kayıtlı")

    # Planın süresi dolmuş mu?
    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires:
            conn.close()
            raise HTTPException(status_code=402, detail="Lisans süresi dolmuş")

    # İlk aktivasyon
    if not row["mac"]:
        conn.execute(
            "UPDATE licenses SET mac=?, activated_at=? WHERE key=?",
            (mac_hash, datetime.utcnow().isoformat(), req.key.upper())
        )
        conn.commit()

    conn.close()
    return {
        "status": "ok",
        "plan": row["plan"],
        "message": "Lisans geçerli",
        "expires_at": row["expires_at"]
    }


@app.post("/license/verify")
def verify_license(req: ActivateRequest):
    """Her açılışta lisans doğrula."""
    mac_hash = hash_mac(req.mac)
    conn = get_db()

    row = conn.execute("SELECT * FROM licenses WHERE key=?", (req.key.upper(),)).fetchone()

    if row is None or not row["active"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Geçersiz veya iptal edilmiş lisans")

    if row["mac"] != mac_hash:
        conn.close()
        raise HTTPException(status_code=409, detail="Bu key başka bir cihaza kayıtlı")

    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires:
            conn.close()
            raise HTTPException(status_code=402, detail="Lisans süresi dolmuş")

    conn.close()
    return {"status": "ok", "plan": row["plan"]}

# ── Admin Endpointleri ─────────────────────────────────────────────────────

@app.post("/admin/keys/create", dependencies=[Depends(check_admin)])
def create_keys(req: CreateKeyRequest):
    """Yeni key(ler) oluştur."""
    conn = get_db()
    keys = []
    for _ in range(min(req.count, 100)):
        key = generate_key()
        conn.execute(
            "INSERT INTO licenses (key, plan, note, created_at) VALUES (?, ?, ?, ?)",
            (key, req.plan, req.note, datetime.utcnow().isoformat())
        )
        keys.append(key)
    conn.commit()
    conn.close()
    return {"keys": keys}


@app.post("/admin/keys/revoke", dependencies=[Depends(check_admin)])
def revoke_key(req: RevokeRequest):
    """Key'i iptal et."""
    conn = get_db()
    conn.execute("UPDATE licenses SET active=0 WHERE key=?", (req.key.upper(),))
    conn.commit()
    conn.close()
    return {"status": "iptal edildi"}


@app.get("/admin/keys", dependencies=[Depends(check_admin)])
def list_keys(active_only: bool = False):
    """Tüm key listesi."""
    conn = get_db()
    query = "SELECT * FROM licenses"
    if active_only:
        query += " WHERE active=1"
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/admin/trials", dependencies=[Depends(check_admin)])
def list_trials():
    """Trial listesi."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM trials ORDER BY first_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/admin/stats", dependencies=[Depends(check_admin)])
def stats():
    """Özet istatistik."""
    conn = get_db()
    total_keys = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    active_keys = conn.execute("SELECT COUNT(*) FROM licenses WHERE active=1").fetchone()[0]
    activated = conn.execute("SELECT COUNT(*) FROM licenses WHERE mac IS NOT NULL").fetchone()[0]
    total_trials = conn.execute("SELECT COUNT(*) FROM trials").fetchone()[0]
    conn.close()
    return {
        "toplam_key": total_keys,
        "aktif_key": active_keys,
        "aktive_edilmis": activated,
        "toplam_trial": total_trials
    }


# ── Admin Web Paneli ───────────────────────────────────────────────────────

@app.get("/admin/panel", response_class=HTMLResponse)
def admin_panel():
    return """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Anons Admin</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0f0f14; color: #e8e8f0; padding: 24px; }
  h1 { color: #e8c547; margin-bottom: 24px; }
  h2 { color: #e8c547; margin: 20px 0 10px; font-size: 14px; }
  .card { background: #1a1a24; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  input, select { background: #0f0f14; color: #e8e8f0; border: 1px solid #3d3d52;
    padding: 8px 12px; border-radius: 4px; font-family: monospace; width: 100%; margin-bottom: 8px; }
  button { background: #2980b9; color: white; border: none; padding: 8px 16px;
    border-radius: 4px; cursor: pointer; font-family: monospace; margin-right: 8px; }
  button.red { background: #c0392b; }
  button.green { background: #27ae60; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #0f0f14; color: #e8c547; padding: 8px; text-align: left; }
  td { padding: 8px; border-bottom: 1px solid #2a2a38; }
  .badge { padding: 2px 8px; border-radius: 10px; font-size: 11px; }
  .active { background: #1a3a2a; color: #27ae60; }
  .inactive { background: #3a1a1a; color: #c0392b; }
  #stats { display: flex; gap: 12px; flex-wrap: wrap; }
  .stat { background: #0f0f14; padding: 12px 20px; border-radius: 6px; text-align: center; }
  .stat .n { font-size: 28px; font-weight: bold; color: #e8c547; }
  .stat .l { font-size: 11px; color: #6b6b80; }
  #msg { color: #e8c547; margin-top: 8px; min-height: 20px; }
</style>
</head>
<body>
<h1>⚙ ANONS — Admin Paneli</h1>

<div class="card">
  <h2>Admin Token</h2>
  <input id="token" type="password" placeholder="Admin token gir..." />
  <button onclick="loadAll()">Giriş / Yenile</button>
  <div id="msg"></div>
</div>

<div class="card">
  <div id="stats"><div class="stat"><div class="n">—</div><div class="l">Yükleniyor</div></div></div>
</div>

<div class="card">
  <h2>Yeni Key Oluştur</h2>
  <input id="plan" placeholder="Plan (lifetime / yearly / monthly)" value="lifetime" />
  <input id="note" placeholder="Not (müşteri adı, sipariş no...)" />
  <input id="count" type="number" value="1" min="1" max="100" placeholder="Kaç adet?" />
  <button class="green" onclick="createKeys()">Oluştur</button>
  <div id="new-keys" style="margin-top:8px;color:#27ae60;word-break:break-all;"></div>
</div>

<div class="card">
  <h2>Key İptal Et</h2>
  <input id="revoke-key" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" />
  <button class="red" onclick="revokeKey()">İptal Et</button>
</div>

<div class="card">
  <h2>Key Listesi</h2>
  <button onclick="loadKeys(false)">Tümü</button>
  <button onclick="loadKeys(true)">Sadece Aktifler</button>
  <div style="overflow-x:auto;margin-top:12px;">
    <table id="key-table">
      <thead><tr><th>Key</th><th>Plan</th><th>Durum</th><th>MAC</th><th>Aktive</th><th>Not</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script>
const base = '';
const tok = () => document.getElementById('token').value;
const msg = (t) => document.getElementById('msg').textContent = t;

async function api(path, method='GET', body=null) {
  const opts = { method, headers: {'x-admin-token': tok(), 'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(base + path, opts);
  if (!r.ok) { msg('Hata: ' + (await r.json()).detail); return null; }
  return r.json();
}

async function loadAll() {
  msg('Yükleniyor...');
  const s = await api('/admin/stats');
  if (!s) return;
  msg('');
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="n">${s.toplam_key}</div><div class="l">Toplam Key</div></div>
    <div class="stat"><div class="n">${s.aktif_key}</div><div class="l">Aktif Key</div></div>
    <div class="stat"><div class="n">${s.aktive_edilmis}</div><div class="l">Aktive Edilmiş</div></div>
    <div class="stat"><div class="n">${s.toplam_trial}</div><div class="l">Trial Kullanıcı</div></div>
  `;
  loadKeys(false);
}

async function loadKeys(activeOnly) {
  const rows = await api('/admin/keys?active_only=' + activeOnly);
  if (!rows) return;
  const tbody = document.querySelector('#key-table tbody');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td style="font-size:11px">${r.key}</td>
      <td>${r.plan}</td>
      <td><span class="badge ${r.active ? 'active':'inactive'}">${r.active ? 'Aktif':'İptal'}</span></td>
      <td style="font-size:10px">${r.mac ? r.mac.substring(0,12)+'...' : '—'}</td>
      <td style="font-size:10px">${r.activated_at ? r.activated_at.substring(0,10) : '—'}</td>
      <td>${r.note || '—'}</td>
    </tr>
  `).join('');
}

async function createKeys() {
  const plan = document.getElementById('plan').value;
  const note = document.getElementById('note').value;
  const count = parseInt(document.getElementById('count').value);
  const res = await api('/admin/keys/create', 'POST', {plan, note, count});
  if (res) {
    document.getElementById('new-keys').textContent = res.keys.join('\\n');
    loadAll();
  }
}

async function revokeKey() {
  const key = document.getElementById('revoke-key').value;
  const res = await api('/admin/keys/revoke', 'POST', {key});
  if (res) { msg('İptal edildi: ' + key); loadAll(); }
}
</script>
</body></html>"""
