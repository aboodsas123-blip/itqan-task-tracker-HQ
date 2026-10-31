"""ITQAN International Investments — simple, multiuser task tracker.
Production requires SECRET_KEY, ITQAN_SETUP_KEY, and a persistent DATABASE_URL.
"""
import hashlib
import hmac
import os
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, BaseLoader, select_autoescape
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

# For production, configure DATABASE_URL, SECRET_KEY, ITQAN_SETUP_KEY in hosting settings.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./itqan-local.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)
SETUP_KEY = os.getenv("ITQAN_SETUP_KEY", "")
SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
Session = sessionmaker(engine, expire_on_commit=False)

def generate_password_hash(password):
    salt = secrets.token_bytes(16)
    iterations = 320_000
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${hashed.hex()}"

def check_password_hash(stored, password):
    try:
        method, iterations, salt, expected = stored.split("$")
        if method != "pbkdf2_sha256": return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False

class Base(DeclarativeBase):
    pass

class Member(Base):
    __tablename__ = "members"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(140))
    position: Mapped[str] = mapped_column(String(140), default="Team Member")
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    password: Mapped[str | None] = mapped_column(Text, nullable=True)
    manager: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    invite_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    invite_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    task: Mapped[str] = mapped_column(String(300))
    assigned_to: Mapped[int] = mapped_column(ForeignKey("members.id"))
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)
    priority: Mapped[str] = mapped_column(String(12), default="Medium")
    status: Mapped[str] = mapped_column(String(20), default="Pending")
    latest_update: Mapped[str] = mapped_column(Text, default="")
    next_action: Mapped[str] = mapped_column(Text, default="")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class History(Base):
    __tablename__ = "history"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(Integer)
    by_name: Mapped[str] = mapped_column(String(140))
    action: Mapped[str] = mapped_column(String(150))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
with Session.begin() as db:
    if not db.scalar(select(func.count(Member.id))):
        for name, position in [
            ("Fahmi Al Kharusi", "CEO"), ("Abdullah", "CFO"),
            ("Fahad", "COO"), ("Feisal", "CBDO"),
            ("Sulaiman", "Tanzania Representative"), ("Fat'h", "Sudan Representative")
        ]:
            db.add(Member(name=name, position=position))

app = FastAPI(title="ITQAN Task Tracker")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=SECURE, max_age=86400 * 14)
views = Environment(loader=BaseLoader(), autoescape=select_autoescape(default=True))
STATUSES = ("Pending", "In Progress", "On Hold", "Completed")
PRIORITIES = ("High", "Medium", "Low")
LOGIN_ATTEMPTS = {}   # Basic process-local throttle. Add provider/WAF throttling for production.

def render(source, **data):
    return HTMLResponse(views.from_string(source).render(**data))

def csrf(request):
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(24)
    return request.session["csrf"]

async def posted(request):
    values = await request.form()
    if not hmac.compare_digest(str(values.get("csrf", "")), csrf(request)):
        raise HTTPException(403, "Security token expired. Reload the page and try again.")
    return values

def get_user(request, db, manager=False):
    user_id = request.session.get("member")
    member = db.get(Member, user_id) if isinstance(user_id, int) else None
    if not member or not member.active or not member.password:
        raise HTTPException(401, "Please sign in.")
    if manager and not member.manager:
        raise HTTPException(403, "Management access required.")
    return member

def redirect(path="/"):
    return RedirectResponse(path, status_code=303)

def positive_id(raw):
    try:
        value = int(raw)
        if value <= 0: raise ValueError()
        return value
    except (ValueError, TypeError):
        raise HTTPException(400, "Select a valid team member.")

def clean(raw, limit=500):
    return str(raw or "").strip()[:limit]

def audit(db, task_id, name, action):
    db.add(History(task_id=task_id, by_name=name, action=action))

def welcome_page(title, inner, token, message=""):
    return render(PAGE, title=title, inner=views.from_string(inner).render(csrf=token, message=message), is_public=True)

PAGE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{{title}} · ITQAN</title>
<style>
:root{--navy:#14243c;--navy2:#213956;--gold:#b49458;--bg:#f6f8fb;--line:#e3e8ee;--text:#243249;--muted:#66758a}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
a{color:#345f9d;text-decoration:none}button,input,select,textarea{font:inherit}button,.btn{background:var(--navy);color:#fff;border:0;border-radius:9px;padding:11px 16px;cursor:pointer;font-weight:650;display:inline-block}button:hover,.btn:hover{opacity:.88}.subtle{background:#eef2f6;color:var(--navy)}.gold{background:var(--gold);color:#fff}.danger{background:#b33d4e}.wrap{max-width:1460px;margin:auto;padding:25px 24px 60px}.top{background:var(--navy);color:#fff;padding:18px 25px}.topinner{max-width:1460px;margin:auto;display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}.brand{font-weight:800;letter-spacing:.6px}.tagline{font-size:12px;color:#dfc58f;margin-top:3px}.topright{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.topright button{background:#334963;padding:9px 12px}.topright a{color:#fff}.hero{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap;margin:12px 0 22px}h1{margin:0;font-size:26px;color:var(--navy)}h2{font-size:18px;color:var(--navy)}.muted{color:var(--muted);font-size:13px}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:15px 0 20px}.stat,.panel,.tablebox{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 2px 8px rgba(12,30,55,.025)}.stat{padding:19px 20px}.stat strong{display:block;font-size:27px;color:var(--navy)}.stat span{font-size:12px;color:var(--muted);text-transform:uppercase;font-weight:700}.panel{padding:20px;margin:16px 0}.filters{display:flex;gap:11px;flex-wrap:wrap;align-items:end}.filters label,.field{display:flex;flex-direction:column;gap:6px;font-size:12px;font-weight:650;color:var(--muted)}input,select,textarea{background:#fff;color:var(--text);border:1px solid #d3dbe6;border-radius:8px;padding:10px;min-width:0}input:focus,select:focus,textarea:focus{outline:2px solid #b0c2dd}input[type=date]{min-height:41px}textarea{resize:vertical;min-height:66px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.full{grid-column:1/-1}.tabs{display:flex;gap:7px;flex-wrap:wrap;margin:16px 0}.tabs a{border:1px solid var(--line);background:#fff;border-radius:100px;padding:9px 14px;color:var(--navy);font-size:13px;font-weight:650}.tabs a.active{background:var(--navy);color:#fff}.tablebox{overflow:auto}table{border-collapse:collapse;width:100%;min-width:1060px}th{background:#eef2f7;color:var(--navy);font-size:12px;text-align:left;padding:14px 12px;white-space:nowrap}td{border-top:1px solid var(--line);padding:13px 12px;vertical-align:top;font-size:13px}td p{margin:3px 0}.taskname{font-weight:750;color:var(--navy)}.small{color:var(--muted);font-size:11px}.pill{display:inline-block;border-radius:30px;font-weight:700;font-size:11px;padding:5px 9px;background:#ecf0f5;color:#55677f}.s-Completed{background:#e2f3e9;color:#23734c}.s-In-Progress{background:#e4effb;color:#235ba0}.s-On-Hold{background:#fff1db;color:#805f21}.p-High,.overdue{color:#b22f3e}.p-High{background:#ffeaed}.overdue{font-weight:800}.actions details{min-width:215px}.actions summary{color:#325f9c;cursor:pointer;font-weight:700}.edit{padding:10px 0;display:grid;gap:8px}.edit label{display:grid;gap:4px;color:var(--muted);font-size:12px}.edit input,.edit select,.edit textarea{width:100%}.formrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.empty{text-align:center;padding:35px;color:var(--muted)}details>summary{cursor:pointer;font-weight:700;color:var(--navy)}details.panel>summary{list-style-position:inside}.login{max-width:490px;margin:65px auto;padding:28px;background:#fff;border:1px solid var(--line);border-radius:15px}.login form{display:grid;gap:13px}.notice{padding:11px 15px;background:#fff7e7;border:1px solid #ebd7ad;border-radius:8px;margin:12px 0}.people{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:13px}.person{padding:16px;border:1px solid var(--line);border-radius:12px}.person form{display:grid;gap:9px;margin-top:10px}.footer{font-size:12px;color:var(--muted);margin-top:25px;text-align:center}
@media(max-width:800px){.wrap{padding:18px 12px 40px}.stats{grid-template-columns:repeat(2,1fr)}.stat{padding:14px}.grid{grid-template-columns:1fr}.top{padding:17px 14px}.hero h1{font-size:22px}.tablebox{background:none;border:0;box-shadow:none;overflow:visible}table,tbody,tr,td{display:block;width:100%;min-width:0}thead{display:none}tr{background:#fff;border:1px solid var(--line);border-radius:12px;margin-bottom:12px;padding:7px;box-shadow:0 2px 6px #00000005}td{display:flex;justify-content:space-between;gap:14px;text-align:right;border:0;padding:8px 9px;overflow-wrap:anywhere}td:before{content:attr(data-label);color:var(--muted);font-size:12px;font-weight:700;text-align:left;min-width:92px}.actions{display:block}.actions:before{display:block;margin-bottom:6px}.actions details{text-align:left}.filters>*{flex:1;min-width:120px}}
</style></head><body>
<header class="top"><div class="topinner"><div><div class="brand">ITQAN <span style="color:var(--gold)">INTERNATIONAL INVESTMENTS</span></div><div class="tagline">ONE WORKSPACE · ONE TEAM · CLEAR ACCOUNTABILITY</div></div>
{% if not is_public %}<div class="topright"><span style="font-size:13px">{{me.name}} {% if me.manager %}· Management{% endif %}</span><a href="/">Tasks</a>{% if me.manager %}<a href="/team">Team Members</a>{% endif %}<button onclick="navigator.clipboard.writeText(location.origin).then(()=>alert('Workspace link copied'))">Copy Link</button><button onclick="window.open('https://wa.me/?text='+encodeURIComponent('ITQAN Task Tracker: '+location.origin),'_blank')">WhatsApp</button><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button type="submit">Sign Out</button></form></div>{% endif %}</div></header>
{% if is_public %}{{inner|safe}}{% else %}<main class="wrap">{{inner|safe}}</main>{% endif %}
</body></html>"""

LOGIN = """<div class="login"><h1>Team Sign In</h1><p class="muted">Use your approved ITQAN account.</p>
{% if message %}<div class="notice">{{message}}</div>{% endif %}<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{csrf}}"><label class="field">Email<input type="email" name="email" autocomplete="username" required></label>
<label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label><button>Sign In</button></form></div>"""
SETUP = """<div class="login"><h1>Activate First Manager</h1><p class="muted">Only ITQAN's approved manager should complete this once. Keep the setup key private.</p>
{% if message %}<div class="notice">{{message}}</div>{% endif %}<form method="post" action="/setup"><input type="hidden" name="csrf" value="{{csrf}}">
<label class="field">Select approved manager<select name="member_id" required>{% for p in members %}<option value="{{p.id}}">{{p.name}} · {{p.position}}</option>{% endfor %}</select></label>
<label class="field">Work email<input type="email" name="email" required></label><label class="field">Password (12+ characters)<input type="password" name="password" minlength="12" required></label>
<label class="field">Private setup key<input type="password" name="key" required></label><button>Activate</button></form></div>"""
JOIN = """<div class="login"><h1>Activate Your Account</h1><p class="muted">{{member.name}} · {{member.position}}</p>
{% if message %}<div class="notice">{{message}}</div>{% endif %}<form method="post">
<input type="hidden" name="csrf" value="{{csrf}}"><label class="field">Create password (12+ characters)<input type="password" name="password" minlength="12" required></label><button>Activate Login</button></form></div>"""

WORKSPACE = r"""<section class="hero"><div><h1>Team Task Tracker</h1><div class="muted">Oman · Tanzania · Sudan · All tasks in one shared register</div></div>{% if me.manager %}<a class="btn gold" href="#new-task">+ New Task</a>{% endif %}</section>
<div class="stats"><div class="stat"><strong>{{counts.total}}</strong><span>Total Tasks</span></div><div class="stat"><strong>{{counts.pending}}</strong><span>Pending</span></div><div class="stat"><strong>{{counts.progress}}</strong><span>In Progress</span></div><div class="stat"><strong>{{counts.completed}}</strong><span>Completed</span></div></div>
{% if me.manager %}<details class="panel" id="new-task"><summary>+ Add New Task</summary><form action="/tasks" method="post" class="grid" style="margin-top:17px"><input type="hidden" name="csrf" value="{{csrf}}">
<label class="field full">Task<input name="task" maxlength="300" placeholder="Short, action-oriented description" required></label>
<label class="field">Assigned To<select name="assigned_to" required>{% for p in members if p.active %}<option value="{{p.id}}">{{p.name}} · {{p.position}}</option>{% endfor %}</select></label>
<label class="field">Deadline<input type="date" name="deadline"></label>
<label class="field">Priority<select name="priority">{% for p in priorities %}<option {{'selected' if p=='Medium' else ''}}>{{p}}</option>{% endfor %}</select></label>
<label class="field">Status<select name="status">{% for s in statuses %}<option>{{s}}</option>{% endfor %}</select></label>
<label class="field">Latest Update<textarea name="latest_update" maxlength="1500"></textarea></label>
<label class="field">Next Action<textarea name="next_action" maxlength="1500"></textarea></label>
<div class="full"><button type="submit">Create Task</button></div></form></details>{% endif %}
<div class="tabs">{% for key,label in [('all','All Tasks'),('mine','My Tasks'),('completed','Completed'),('overdue','Overdue')] + ([('archived','Archived')] if me.manager else []) %}<a href="/?view={{key}}" class="{{'active' if view==key else ''}}">{{label}}</a>{% endfor %}</div>
<div class="panel"><form method="get" class="filters"><input type="hidden" name="view" value="{{view}}">
<label>Search<input name="q" value="{{q}}" placeholder="Search tasks and remarks"></label>
<label>Assigned To<select name="person"><option value="">Everyone</option>{% for p in members %}<option value="{{p.id}}" {{'selected' if person==p.id else ''}}>{{p.name}}</option>{% endfor %}</select></label>
<label>Status<select name="status"><option value="">All statuses</option>{% for s in statuses %}<option {{'selected' if selected_status==s else ''}}>{{s}}</option>{% endfor %}</select></label>
<label>Priority<select name="priority"><option value="">All priorities</option>{% for p in priorities %}<option {{'selected' if selected_priority==p else ''}}>{{p}}</option>{% endfor %}</select></label>
<label>Deadline<select name="due"><option value="">Any date</option><option value="overdue" {{'selected' if due=='overdue' else ''}}>Overdue</option><option value="week" {{'selected' if due=='week' else ''}}>Next 7 days</option><option value="none" {{'selected' if due=='none' else ''}}>No deadline</option></select></label>
<button type="submit">Filter</button><a class="btn subtle" href="/">Clear</a></form></div>
<div class="tablebox"><table><thead><tr><th>Task</th><th>Assigned To</th><th>Deadline</th><th>Priority</th><th>Status</th><th>Latest Update</th><th>Next Action</th><th>Actions</th></tr></thead><tbody>
{% for t in tasks %}<tr><td data-label="Task"><div><span class="taskname">{{t.task}}</span><div class="small">ITQ-{{'%05d'|format(t.id)}}</div></div></td>
<td data-label="Assigned To">{{names.get(t.assigned_to,'Unknown')}}</td>
<td data-label="Deadline"><span class="{{'overdue' if t.deadline and t.deadline < today and t.status!='Completed' and not t.archived else ''}}">{{t.deadline.strftime('%d %b %Y') if t.deadline else '—'}}{% if t.deadline and t.deadline < today and t.status!='Completed' and not t.archived %} · OVERDUE{% endif %}</span></td>
<td data-label="Priority"><span class="pill p-{{t.priority}}">{{t.priority}}</span></td>
<td data-label="Status"><span class="pill s-{{t.status|replace(' ','-')}}">{{t.status}}</span></td>
<td data-label="Latest Update">{{t.latest_update or '—'}}</td><td data-label="Next Action">{{t.next_action or '—'}}</td>
<td data-label="Actions" class="actions"><details><summary>{{'Edit' if me.manager else ('Update' if t.assigned_to==me.id else 'View')}} Task</summary>
{% if me.manager or (t.assigned_to==me.id and not t.archived) %}<form class="edit" method="post" action="/tasks/{{t.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{t.version}}">
{% if me.manager %}<label>Task<input name="task" value="{{t.task}}" required></label><label>Assigned To<select name="assigned_to">{% for p in members if p.active or p.id==t.assigned_to %}<option value="{{p.id}}" {{'selected' if p.id==t.assigned_to else ''}}>{{p.name}}</option>{% endfor %}</select></label><label>Deadline<input name="deadline" type="date" value="{{t.deadline.isoformat() if t.deadline else ''}}"></label><label>Priority<select name="priority">{% for p in priorities %}<option {{'selected' if p==t.priority else ''}}>{{p}}</option>{% endfor %}</select></label>{% endif %}
<label>Status<select name="status">{% for s in statuses %}<option {{'selected' if s==t.status else ''}}>{{s}}</option>{% endfor %}</select></label><label>Latest Update<textarea name="latest_update" maxlength="1500">{{t.latest_update}}</textarea></label><label>Next Action<textarea name="next_action" maxlength="1500">{{t.next_action}}</textarea></label><button>Save Changes</button></form>{% endif %}
{% if me.manager %}<form method="post" action="/tasks/{{t.id}}/archive" onsubmit="return confirm('Confirm archive/restore?')"><input type="hidden" name="csrf" value="{{csrf}}"><button class="subtle">{{'Restore' if t.archived else 'Archive'}}</button></form>{% endif %}
<a class="small" href="/tasks/{{t.id}}/history">View history</a></details></td></tr>{% else %}<tr><td colspan="8" class="empty">No tasks found. {% if me.manager %}Use “Add New Task” to begin.{% endif %}</td></tr>{% endfor %}</tbody></table></div>
<div class="footer">Changes are saved in the shared database. Open pages check for new updates every 15 seconds.</div>
<script>const currentRev={{revision|tojson}};setInterval(async()=>{if(document.hidden||document.querySelector('details[open]')||document.activeElement?.matches('input,textarea,select'))return;try{const r=await fetch('/api/revision',{credentials:'same-origin'});if(r.ok){const d=await r.json();if(d.revision!==currentRev)location.reload();}}catch(e){}},15000);</script>"""

TEAM = """<div class="hero"><div><h1>Team Members</h1><p class="muted">Invite or deactivate users; management controls access.</p></div><a class="btn subtle" href="/">Back to Tasks</a></div>
{% if invite_link %}<div class="notice"><strong>Private one-time invitation link:</strong><br><input style="width:100%" readonly value="{{invite_link}}" onclick="this.select()"><p class="muted">Send this link privately. It expires in seven days and works once. Do not post it to the group.</p></div>{% endif %}
<details class="panel"><summary>+ Add Team Member</summary><form method="post" action="/team" class="grid" style="margin-top:14px"><input type="hidden" name="csrf" value="{{csrf}}"><label class="field">Full Name<input name="name" required maxlength="140"></label><label class="field">Position<input name="position" required maxlength="140"></label><div class="full"><button>Add Member</button></div></form></details>
<div class="people">{% for p in members %}<div class="panel person"><strong>{{p.name}}</strong><div class="muted">{{p.position}} · {{'Management' if p.manager else 'Team Member'}}</div><div class="muted">{{p.email or 'Not invited'}} · {{'Active' if p.active else 'Inactive'}}</div>
{% if p.active %}<form method="post" action="/team/{{p.id}}/invite"><input type="hidden" name="csrf" value="{{csrf}}"><label class="field">Work Email<input type="email" name="email" value="{{p.email or ''}}" required></label><label class="field">Access<select name="manager"><option value="0" {{'selected' if not p.manager else ''}}>Team Member</option><option value="1" {{'selected' if p.manager else ''}}>Management</option></select></label><button class="subtle">{{'Reset Login' if p.password else 'Generate Invite'}}</button></form>{% endif %}
{% if p.id!=me.id %}<form method="post" action="/team/{{p.id}}/toggle"><input type="hidden" name="csrf" value="{{csrf}}"><button class="{{'danger' if p.active else 'subtle'}}">{{'Deactivate' if p.active else 'Reactivate'}}</button></form>{% endif %}</div>{% endfor %}</div>"""

HISTORY_PAGE = """<div class="hero"><div><h1>Task History</h1><p class="muted">ITQ-{{'%05d'|format(task.id)}} · {{task.task}}</p></div><a class="btn subtle" href="/">Back to Tasks</a></div><div class="panel"><table style="min-width:0"><thead><tr><th>When</th><th>Changed By</th><th>Action</th></tr></thead><tbody>{% for row in items %}<tr><td data-label="When">{{row.at.strftime('%d %b %Y %H:%M UTC')}}</td><td data-label="Changed By">{{row.by_name}}</td><td data-label="Action">{{row.action}}</td></tr>{% endfor %}</tbody></table></div>"""

def page(req, me, content, **values):
    part = views.from_string(content).render(me=me, csrf=csrf(req), **values)
    return render(PAGE, title="Task Tracker", inner=part, is_public=False, me=me, csrf=csrf(req))

def manager_exists(db):
    return db.scalar(select(func.count(Member.id)).where(Member.manager == True, Member.password.is_not(None))) > 0

@app.get("/health")
def health():
    with Session() as db:
        db.execute(select(func.count(Member.id))).scalar_one()
    return {"ok": True}

@app.get("/setup", response_class=HTMLResponse)
def setup_get(request: Request):
    with Session() as db:
        if manager_exists(db): return redirect("/login")
        members = db.scalars(select(Member).order_by(Member.id)).all()
    content = views.from_string(SETUP).render(csrf=csrf(request), members=members)
    return render(PAGE, title="First Setup", inner=content, is_public=True)

@app.post("/setup")
async def setup_post(request: Request):
    f = await posted(request)
    with Session.begin() as db:
        if manager_exists(db): raise HTTPException(403, "Already activated")
        if not SETUP_KEY or not hmac.compare_digest(str(f.get("key", "")), SETUP_KEY): raise HTTPException(403, "Invalid setup key")
        m = db.get(Member, positive_id(f.get("member_id")))
        if not m: raise HTTPException(400, "Invalid team member")
        email = clean(f.get("email"), 255).lower()
        password = str(f.get("password", ""))
        if "@" not in email or len(password) < 12: raise HTTPException(400, "Use a valid email and a password of 12+ characters")
        m.email, m.password, m.manager = email, generate_password_hash(password), True
        request.session.clear()
        request.session["member"] = m.id
    return redirect("/")

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    with Session() as db:
        first = not manager_exists(db)
    if first: return redirect("/setup")
    return welcome_page("Sign In", LOGIN, csrf(request))

@app.post("/login")
async def login_post(request: Request):
    f = await posted(request)
    ip = request.client.host if request.client else "unknown"
    recent = [t for t in LOGIN_ATTEMPTS.get(ip, []) if time.time()-t < 300]
    if len(recent) >= 10: raise HTTPException(429, "Too many attempts. Try again later.")
    email = clean(f.get("email"), 255).lower()
    with Session() as db:
        m = db.scalar(select(Member).where(Member.email == email, Member.active == True))
        good = bool(m and m.password and check_password_hash(m.password, str(f.get("password", ""))))
        if good: member_id = m.id
    if not good:
        LOGIN_ATTEMPTS[ip] = recent + [time.time()]
        return welcome_page("Sign In", LOGIN, csrf(request), "Incorrect email or password")
    LOGIN_ATTEMPTS.pop(ip, None)
    request.session.clear()
    request.session["member"] = member_id
    return redirect("/")

@app.post("/logout")
async def logout(request: Request):
    await posted(request)
    request.session.clear()
    return redirect("/login")

@app.get("/join/{token}", response_class=HTMLResponse)
def join_get(request: Request, token: str):
    key = hashlib.sha256(token.encode()).hexdigest()
    with Session() as db:
        m = db.scalar(select(Member).where(Member.invite_hash == key, Member.active == True))
        if not m or not m.invite_expires or m.invite_expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc): raise HTTPException(410, "This invitation link expired or was already used")
        member = {"name": m.name, "position": m.position}
    return render(PAGE, title="Join ITQAN", is_public=True, inner=views.from_string(JOIN).render(member=member, csrf=csrf(request)))

@app.post("/join/{token}")
async def join_post(request: Request, token: str):
    f = await posted(request)
    password = str(f.get("password", ""))
    if len(password) < 12: raise HTTPException(400, "Password must contain at least 12 characters")
    key = hashlib.sha256(token.encode()).hexdigest()
    with Session.begin() as db:
        m = db.scalar(select(Member).where(Member.invite_hash == key, Member.active == True))
        if not m or not m.invite_expires or m.invite_expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc): raise HTTPException(410, "This invitation link expired or was already used")
        m.password = generate_password_hash(password)
        m.invite_hash, m.invite_expires = None, None
        member_id = m.id
    request.session.clear()
    request.session["member"] = member_id
    return redirect("/")

def revision(db):
    # Includes archived items; monotonic updated_at from writes.
    last_task = db.scalar(select(func.max(Task.updated_at)))
    last_hist = db.scalar(select(func.max(History.at)))
    return f"{last_task or ''}|{last_hist or ''}|{db.scalar(select(func.count(Task.id)))}"

@app.get("/api/revision")
def revision_get(request: Request):
    with Session() as db:
        get_user(request, db)
        return {"revision": revision(db)}

@app.get("/", response_class=HTMLResponse)
def index(request: Request, view: str="all", q: str="", person: int | None=None, status: str="", priority: str="", due: str=""):
    with Session() as db:
        try: me = get_user(request, db)
        except HTTPException: return redirect("/login")
        today = datetime.now(ZoneInfo("Asia/Muscat")).date()
        members = db.scalars(select(Member).order_by(Member.id)).all()
        names = {m.id:m.name for m in members}
        all_active = db.scalars(select(Task).where(Task.archived == False)).all()
        counts = dict(total=len(all_active),pending=sum(t.status=="Pending" for t in all_active),progress=sum(t.status=="In Progress" for t in all_active),completed=sum(t.status=="Completed" for t in all_active))
        query = select(Task)
        if view=="archived":
            if not me.manager: raise HTTPException(403, "Management only")
            query = query.where(Task.archived == True)
        else: query = query.where(Task.archived == False)
        if view=="mine": query=query.where(Task.assigned_to==me.id)
        if view=="completed": query=query.where(Task.status=="Completed")
        if view=="overdue": query=query.where(Task.deadline < today, Task.status!="Completed")
        if person: query=query.where(Task.assigned_to==person)
        if status in STATUSES: query=query.where(Task.status==status)
        if priority in PRIORITIES: query=query.where(Task.priority==priority)
        if due=="overdue": query=query.where(Task.deadline < today, Task.status!="Completed")
        if due=="week": query=query.where(Task.deadline>=today,Task.deadline<=today+timedelta(days=7))
        if due=="none": query=query.where(Task.deadline.is_(None))
        if q.strip():
            pattern=f"%{q.strip()[:100]}%"
            query=query.where(Task.task.ilike(pattern) | Task.latest_update.ilike(pattern) | Task.next_action.ilike(pattern))
        tasks=db.scalars(query.order_by(Task.deadline.is_(None),Task.deadline,Task.id.desc()).limit(1000)).all()
        rev=revision(db)
        return page(request,me,WORKSPACE,tasks=tasks,counts=counts,members=members,names=names,priorities=PRIORITIES,statuses=STATUSES,today=today,view=view,q=q,person=person,selected_status=status,selected_priority=priority,due=due,revision=rev)

@app.post("/tasks")
async def task_create(request: Request):
    f=await posted(request)
    with Session.begin() as db:
        me=get_user(request,db,True)
        name=clean(f.get("task"),300)
        assigned=positive_id(f.get("assigned_to"))
        assignee=db.get(Member,assigned)
        if not name or not assignee or not assignee.active: raise HTTPException(400,"Enter a task and an active team member")
        deadline=clean(f.get("deadline"))
        try: parsed=date.fromisoformat(deadline) if deadline else None
        except ValueError: raise HTTPException(400,"Invalid deadline")
        priority=clean(f.get("priority"))
        status=clean(f.get("status"))
        if priority not in PRIORITIES or status not in STATUSES: raise HTTPException(400,"Invalid priority or status")
        existing=db.scalar(select(Task).where(func.lower(Task.task)==name.lower(),Task.assigned_to==assigned,Task.archived==False))
        if existing: raise HTTPException(409,"A task with this description and assignee already exists")
        t=Task(task=name,assigned_to=assigned,deadline=parsed,priority=priority,status=status,latest_update=clean(f.get("latest_update"),1500),next_action=clean(f.get("next_action"),1500))
        db.add(t); db.flush(); audit(db,t.id,me.name,"Task created")
    return redirect("/")

@app.post("/tasks/{task_id}")
async def task_update(request: Request,task_id:int):
    f=await posted(request)
    with Session.begin() as db:
        me=get_user(request,db)
        t=db.get(Task,task_id)
        if not t or (t.archived and not me.manager): raise HTTPException(404,"Task not found")
        if not me.manager and t.assigned_to!=me.id: raise HTTPException(403,"Only the assignee can update this task")
        if int(f.get("version",0))!=t.version: raise HTTPException(409,"Someone updated this task. Reload to view the latest changes.")
        status=clean(f.get("status"))
        if status not in STATUSES: raise HTTPException(400,"Invalid status")
        changed=[]
        for field,value in (("status",status),("latest_update",clean(f.get("latest_update"),1500)),("next_action",clean(f.get("next_action"),1500))):
            if getattr(t,field)!=value: setattr(t,field,value); changed.append(field)
        if me.manager:
            name=clean(f.get("task"),300)
            assigned=positive_id(f.get("assigned_to"))
            assignee=db.get(Member,assigned)
            if not name or not assignee or not assignee.active: raise HTTPException(400,"Task and active assignee required")
            deadline=clean(f.get("deadline"))
            try: parsed=date.fromisoformat(deadline) if deadline else None
            except ValueError: raise HTTPException(400,"Invalid deadline")
            priority=clean(f.get("priority"))
            if priority not in PRIORITIES: raise HTTPException(400,"Invalid priority")
            for field,value in (("task",name),("assigned_to",assigned),("deadline",parsed),("priority",priority)):
                if getattr(t,field)!=value: setattr(t,field,value); changed.append(field)
        if changed:
            t.version+=1;t.updated_at=datetime.now(timezone.utc)
            audit(db,t.id,me.name,"Updated: "+", ".join(changed))
    return redirect("/")

@app.post("/tasks/{task_id}/archive")
async def task_archive(request:Request,task_id:int):
    await posted(request)
    with Session.begin() as db:
        me=get_user(request,db,True)
        t=db.get(Task,task_id)
        if not t: raise HTTPException(404,"Task not found")
        t.archived=not t.archived;t.version+=1;t.updated_at=datetime.now(timezone.utc)
        audit(db,t.id,me.name,"Restored" if not t.archived else "Archived")
    return redirect("/?view=archived" if t.archived else "/")

@app.get("/tasks/{task_id}/history")
def history_get(request:Request,task_id:int):
    with Session() as db:
        me=get_user(request,db)
        t=db.get(Task,task_id)
        if not t: raise HTTPException(404,"Task not found")
        items=db.scalars(select(History).where(History.task_id==task_id).order_by(History.id.desc())).all()
        return page(request,me,HISTORY_PAGE,task=t,items=items)

@app.get("/team",response_class=HTMLResponse)
def team_get(request:Request):
    with Session() as db:
        me=get_user(request,db,True)
        members=db.scalars(select(Member).order_by(Member.id)).all()
        return page(request,me,TEAM,members=members,invite_link=None)

@app.post("/team")
async def team_create(request:Request):
    f=await posted(request)
    with Session.begin() as db:
        get_user(request,db,True)
        name=clean(f.get("name"),140);position=clean(f.get("position"),140) or "Team Member"
        if len(name)<2: raise HTTPException(400,"Enter a name")
        db.add(Member(name=name,position=position))
    return redirect("/team")

@app.post("/team/{member_id}/invite")
async def invite(request:Request,member_id:int):
    f=await posted(request)
    with Session.begin() as db:
        me=get_user(request,db,True)
        m=db.get(Member,member_id)
        if not m or not m.active: raise HTTPException(404,"Active member not found")
        email=clean(f.get("email"),255).lower()
        if "@" not in email or "." not in email: raise HTTPException(400,"Valid work email required")
        conflict=db.scalar(select(Member).where(Member.email==email,Member.id!=member_id))
        if conflict: raise HTTPException(409,"Email is already assigned to another member")
        requested_manager=f.get("manager")=="1"
        if m.id==me.id and not requested_manager: raise HTTPException(400,"You cannot remove your own management access")
        m.email=email;m.manager=requested_manager
        token=secrets.token_urlsafe(40)
        m.invite_hash=hashlib.sha256(token.encode()).hexdigest()
        m.invite_expires=datetime.now(timezone.utc)+timedelta(days=7)
        members=db.scalars(select(Member).order_by(Member.id)).all()
        # Generated link is displayed once, never stored in plaintext.
        external_base=os.getenv("PUBLIC_BASE_URL","").rstrip("/") or str(request.base_url).rstrip("/")
        link=f"{external_base}/join/{token}"
        result=page(request,me,TEAM,members=members,invite_link=link)
    return result

@app.post("/team/{member_id}/toggle")
async def team_toggle(request:Request,member_id:int):
    await posted(request)
    with Session.begin() as db:
        me=get_user(request,db,True)
        m=db.get(Member,member_id)
        if not m or m.id==me.id: raise HTTPException(400,"Cannot change your own access")
        if m.active:
            active_count=db.scalar(select(func.count(Task.id)).where(Task.assigned_to==m.id,Task.archived==False,Task.status!="Completed"))
            if active_count: raise HTTPException(409,"Reassign or complete this member's outstanding tasks first")
        m.active=not m.active
    return redirect("/team")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,host="127.0.0.1",port=int(os.getenv("PORT","8000")))