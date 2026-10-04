import os
import io
import hmac
import time
import json
import secrets
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from datetime import date, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_file, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from database import get_db, init_db, DB_PATH, log_activity

# ================================================================== الإعدادات (Production)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# تحميل متغيرات البيئة من ملف .env إن وُجد (اختياري، بدون أي حزمة خارجية)
def _load_dotenv(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env_bool(name, default=False):
    """قراءة قيمة منطقية من متغيرات البيئة (1/true/yes/on)."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _load_secret_key():
    """
    المفتاح السرّي للجلسات:
    1) من متغير البيئة SECRET_KEY (الطريقة الموصى بها في الإنتاج).
    2) وإلا يُولَّد مرة واحدة ويُحفظ في instance/secret.key (بدل مفتاح ثابت داخل الكود).
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    instance_dir = os.path.join(BASE_DIR, "instance")
    key_path = os.path.join(instance_dir, "secret.key")
    try:
        os.makedirs(instance_dir, exist_ok=True)
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as fh:
                stored = fh.read().strip()
            if stored:
                return stored
        key = secrets.token_hex(32)
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        app_logger = logging.getLogger("app")
        app_logger.warning("تعذّر حفظ المفتاح السرّي على القرص — سيتم استخدام مفتاح عشوائي للجلسات الحالية.")
        return secrets.token_hex(32)


DEBUG = _env_bool("FLASK_DEBUG", False)
ENABLE_CSP = _env_bool("ENABLE_CSP", True)
BEHIND_PROXY = _env_bool("BEHIND_PROXY", False)
SHOW_DEMO_ACCOUNTS = _env_bool("SHOW_DEMO_ACCOUNTS", False)
_DEMO_FLAG_SET = os.environ.get("SHOW_DEMO_ACCOUNTS") is not None

app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_NAME=os.environ.get("SESSION_COOKIE_NAME", "tollroad_session"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", False),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "12"))),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,  # حد أقصى 8MB للاستمارات المرسلة
)

# دعم العمل خلف واجهة عكسية (Nginx/Apache/LB): عناوين IP وبروتوكول HTTP الحقيقيين
if BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# ------------------------------ التسجيل (logging) إلى ملف مع تدوير
LOG_DIR = os.path.join(BASE_DIR, "logs")
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "app.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    _file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    _file_handler.setLevel(logging.INFO)
    app.logger.addHandler(_file_handler)
except OSError:
    pass  # التشغيل لا يتوقف إن تعذّرت الكتابة على القرص
app.logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
if DEBUG:
    app.logger.warning("FLASK_DEBUG=1 — وضع التطوير مفعّل.")

ROLE_LABELS = {"admin": "مدير النظام", "manager": "مشرف", "viewer": "اطلاع فقط"}
APP_NAME_AR = "إدارة خدمات الطريق الدولي"
APP_NAME_EN = "Toll Road Services Management"

# كلمات المرور الافتراضية التي يجب تغييرها فورًا قبل الإنتاج
DEFAULT_PASSWORDS = {"admin": "admin123", "manager": "manager123", "viewer": "viewer123"}
DEFAULT_PASSWORD_USERS = []
_default_pw_checked = False


def ensure_db():
    """ينشئ القاعدة إن كانت غير موجودة أو فارغة/تالفة (بدون جدول المستخدمين)."""
    ok = False
    if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) > 0:
        try:
            db = get_db()
            ok = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone() is not None
            db.close()
        except Exception:
            ok = False
    if not ok:
        init_db(seed=True)


def _check_default_passwords():
    """يفحص مرة واحدة إن كانت الحسابات ما زالت تستخدم كلمات المرور الافتراضية."""
    global _default_pw_checked
    if _default_pw_checked:
        return
    _default_pw_checked = True
    DEFAULT_PASSWORD_USERS.clear()
    try:
        db = get_db()
        for username, password in DEFAULT_PASSWORDS.items():
            row = db.execute(
                "SELECT password_hash FROM users WHERE username = ? AND active = 1", (username,)
            ).fetchone()
            if row and check_password_hash(row["password_hash"], password):
                DEFAULT_PASSWORD_USERS.append(username)
        db.close()
    except Exception:
        app.logger.exception("تعذّر فحص كلمات المرور الافتراضية")
    if DEFAULT_PASSWORD_USERS:
        app.logger.warning(
            "تنبيه أمني: هذه الحسابات ما زالت تستخدم كلمات المرور الافتراضية: %s",
            ", ".join(DEFAULT_PASSWORD_USERS),
        )


def _client_ip():
    """عنوان العميل (يدعم التمرير خلف Proxy عند تفعيل BEHIND_PROXY)."""
    if BEHIND_PROXY:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _safe_next(target):
    """منع التحويل إلى روابط خارجية (Open Redirect)."""
    if not target:
        return None
    if not target.startswith("/") or target.startswith("//") or "\\" in target or "://" in target:
        return None
    return target


# ================================================================== حماية CSRF لجميع عمليات POST
def csrf_token():
    """توليد رمز حماية للجلسة و توفيره للقوالب عبر {{ csrf_token() }}."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _verify_csrf():
    if request.method != "POST":
        return None
    expected = session.get("csrf_token")
    provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not provided or not hmac.compare_digest(str(provided), expected):
        app.logger.warning("مرفوض (CSRF): %s %s من %s", request.method, request.path, _client_ip())
        flash("انتهت صلاحية الصفحة أو رمز الحماية غير صالح — أعد تحميل الصفحة ثم أعد المحاولة", "error")
        return redirect(_safe_next(request.referrer) or url_for("dashboard"))
    return None


# ================================================================== تقييد محاولات تسجيل الدخول
LOGIN_ATTEMPTS = {}
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW_SECONDS", "900"))
LOGIN_LOCKOUT = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "900"))


def _login_key(username):
    return f"{_client_ip()}|{username}"


def _login_lock_remaining(key):
    """عدد الثواني المتبقية على إيقاف الدخول، أو 0 إن لم يكن مقفولًا."""
    rec = LOGIN_ATTEMPTS.get(key)
    if not rec:
        return 0
    now = time.time()
    if now - rec["window_start"] > LOGIN_WINDOW:
        LOGIN_ATTEMPTS.pop(key, None)
        return 0
    if rec["locked_until"] > now:
        return int(rec["locked_until"] - now) + 1
    return 0


def _register_failed_login(key):
    now = time.time()
    rec = LOGIN_ATTEMPTS.get(key)
    if not rec or now - rec["window_start"] > LOGIN_WINDOW:
        rec = {"count": 0, "window_start": now, "locked_until": 0}
    rec["count"] += 1
    if rec["count"] >= LOGIN_MAX_ATTEMPTS:
        rec["locked_until"] = now + LOGIN_LOCKOUT
        app.logger.warning("قفل الدخول بعد %d محاولات فاشلة: %s", rec["count"], key)
    LOGIN_ATTEMPTS[key] = rec
    if len(LOGIN_ATTEMPTS) > 2000:  # منع تضخم الذاكرة
        for stale in list(LOGIN_ATTEMPTS)[:500]:
            LOGIN_ATTEMPTS.pop(stale, None)


@app.before_request
def _before():
    ensure_db()
    _check_default_passwords()
    if session.get("user_id") and not session.permanent:
        session.permanent = True
    denied = _verify_csrf()
    if denied is not None:
        return denied


# ================================================================== أدوات المصادقة والصلاحيات
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("يجب تسجيل الدخول أولاً", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("يجب تسجيل الدخول أولاً", "error")
                return redirect(url_for("login", next=request.path))
            if session.get("role") not in roles:
                flash("ليست لديك صلاحية القيام بهذا الإجراء", "error")
                return redirect(request.referrer or url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def inject_user():
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "full_name": session.get("full_name"),
            "role": session.get("role"),
            "role_label": ROLE_LABELS.get(session.get("role"), ""),
        },
        "current_user_id": session.get("user_id"),
        "can_edit": session.get("role") in ("admin", "manager"),
        "is_admin": session.get("role") == "admin",
        # الهوية + الحماية
        "csrf_token": csrf_token,
        "app_name": APP_NAME_AR,
        "app_name_en": APP_NAME_EN,
        # إظهار الحسابات التجريبية: يتحكم فيه البيئة، وإلا يظهر تلقائيًا ما دامت
        # كلمات المرور الافتراضية لم تُغيَّر (فيختفي وحده بعد تغييرها في الإنتاج)
        "show_demo_accounts": (
            SHOW_DEMO_ACCOUNTS if _DEMO_FLAG_SET else bool(DEFAULT_PASSWORD_USERS)
        ),
        "default_password_users": DEFAULT_PASSWORD_USERS,
    }


# ================================================================== تسجيل الدخول / الخروج
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        lock_key = _login_key(username)

        lock_remaining = _login_lock_remaining(lock_key)
        if lock_remaining:
            minutes, seconds = divmod(lock_remaining, 60)
            wait = f"{minutes} دقيقة و{seconds} ثانية" if minutes else f"{seconds} ثانية"
            app.logger.warning("محاولة دخول أثناء القفل من %s (%s)", _client_ip(), username)
            flash(f"تم إيقاف محاولات الدخول مؤقتًا — أعد المحاولة بعد {wait}", "error")
            return render_template("login.html"), 429

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1", (username,)
        ).fetchone()

        # مقارنة كلمة المرور (Werkzeug — تحقق بزمن ثابت تقريبًا)
        if user and check_password_hash(user["password_hash"], password):
            LOGIN_ATTEMPTS.pop(lock_key, None)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            session.permanent = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            log_activity(db, username, "تسجيل دخول", "auth")
            db.commit()
            db.close()
            flash(f"مرحبًا بك، {user['full_name']}", "success")
            next_url = _safe_next(request.args.get("next")) or url_for("dashboard")
            return redirect(next_url)

        db.close()
        _register_failed_login(lock_key)
        remaining = _login_lock_remaining(lock_key)
        if remaining:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة — تم قفل الدخول مؤقتًا لمزيد من الحماية", "error")
        else:
            attempts_left = max(LOGIN_MAX_ATTEMPTS - LOGIN_ATTEMPTS.get(lock_key, {}).get("count", 0), 0)
            flash(f"اسم المستخدم أو كلمة المرور غير صحيحة (محاولات متبقية: {attempts_left})", "error")
        app.logger.warning("فشل تسجيل دخول للمستخدم '%s' من %s", username, _client_ip())

    return render_template("login.html")


@app.route("/logout")
def logout():
    if session.get("username"):
        db = get_db()
        log_activity(db, session.get("username"), "تسجيل خروج", "auth")
        db.commit()
        db.close()
    session.clear()
    flash("تم تسجيل الخروج بنجاح", "success")
    return redirect(url_for("login"))


# ================================================================== الرئيسية / لوحة المعلومات
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    today = date.today().isoformat()

    sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()

    attendance_today = db.execute(
        """SELECT s.id as site_id, s.name as site_name,
                  COUNT(a.id) as present_count
           FROM sites s
           LEFT JOIN attendance a ON a.site_id = s.id
                AND a.date = ? AND a.status = 'حاضر'
           GROUP BY s.id ORDER BY s.km_from""",
        (today,),
    ).fetchall()

    total_workers = db.execute("SELECT COUNT(*) c FROM workers WHERE active=1").fetchone()["c"]
    present_today = db.execute(
        "SELECT COUNT(*) c FROM attendance WHERE date=? AND status='حاضر'", (today,)
    ).fetchone()["c"]

    maintenance_due = db.execute(
        """SELECT e.*, s.name as site_name FROM equipment e
           LEFT JOIN sites s ON s.id = e.site_id
           WHERE (e.operating_hours - e.hours_at_last_maint) >= e.maintenance_interval"""
    ).fetchall()

    low_stock = db.execute(
        """SELECT ms.*, m.name as material_name, m.unit, m.min_threshold, s.name as site_name
           FROM material_stock ms
           JOIN materials m ON m.id = ms.material_id
           JOIN sites s ON s.id = ms.site_id
           WHERE ms.quantity < m.min_threshold
           ORDER BY ms.quantity ASC"""
    ).fetchall()

    pending_transfers = db.execute(
        """SELECT t.*, m.name as material_name, m.unit,
                  sf.name as from_name, st.name as to_name
           FROM material_transfers t
           JOIN materials m ON m.id = t.material_id
           LEFT JOIN sites sf ON sf.id = t.from_site_id
           JOIN sites st ON st.id = t.to_site_id
           WHERE t.status = 'قيد الانتظار'
           ORDER BY t.date DESC"""
    ).fetchall()

    # -------- بيانات الرسوم البيانية --------
    # اتجاه الحضور لآخر 7 أيام
    attendance_trend = []
    for i in range(6, -1, -1):
        d = (date.today() - timedelta(days=i)).isoformat()
        c = db.execute(
            "SELECT COUNT(*) c FROM attendance WHERE date=? AND status='حاضر'", (d,)
        ).fetchone()["c"]
        attendance_trend.append({"date": d[5:], "count": c})

    # توزيع حالة المعدات
    equipment_status = db.execute(
        "SELECT status, COUNT(*) c FROM equipment GROUP BY status"
    ).fetchall()

    # قيمة المخزون حسب الموقع
    stock_value = db.execute(
        """SELECT s.name as site_name, ROUND(SUM(ms.quantity * m.cost_per_unit), 0) as value
           FROM material_stock ms
           JOIN materials m ON m.id = ms.material_id
           JOIN sites s ON s.id = ms.site_id
           GROUP BY s.id ORDER BY s.km_from"""
    ).fetchall()

    # الميزانية مقابل المصروف لكل موقع
    budget_data = db.execute(
        "SELECT name, budget, spent, progress_pct FROM sites ORDER BY km_from"
    ).fetchall()

    total_budget = sum(s["budget"] or 0 for s in sites)
    total_spent = sum(s["spent"] or 0 for s in sites)

    db.close()
    return render_template(
        "dashboard.html",
        sites=sites,
        attendance_today=attendance_today,
        total_workers=total_workers,
        present_today=present_today,
        maintenance_due=maintenance_due,
        low_stock=low_stock,
        pending_transfers=pending_transfers,
        attendance_trend=attendance_trend,
        equipment_status=equipment_status,
        stock_value=stock_value,
        budget_data=budget_data,
        total_budget=total_budget,
        total_spent=total_spent,
        today=today,
    )


# ================================================================== المواقع / القواطع
@app.route("/sites", methods=["GET", "POST"])
@login_required
def sites():
    db = get_db()
    if request.method == "POST":
        if session.get("role") not in ("admin", "manager"):
            flash("ليست لديك صلاحية إضافة موقع", "error")
            db.close()
            return redirect(url_for("sites"))
        try:
            name = request.form["name"].strip()
            code = request.form["code"].strip()
            if not name or not code:
                raise ValueError("الاسم والرمز مطلوبان")
            db.execute(
                """INSERT INTO sites (name, code, km_from, km_to, budget, manager_name,
                                       latitude, longitude)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    name, code,
                    request.form.get("km_from") or None,
                    request.form.get("km_to") or None,
                    request.form.get("budget") or 0,
                    request.form.get("manager_name", "").strip() or None,
                    request.form.get("latitude") or None,
                    request.form.get("longitude") or None,
                ),
            )
            log_activity(db, session.get("username"), f"إضافة موقع: {name} ({code})", "sites")
            db.commit()
            flash("تم إضافة الموقع بنجاح", "success")
        except Exception as e:
            db.rollback()
            flash(f"تعذّرت إضافة الموقع: رمز الموقع مستخدم مسبقًا أو بيانات غير صحيحة", "error")
        db.close()
        return redirect(url_for("sites"))

    q = request.args.get("q", "").strip()
    if q:
        all_sites = db.execute(
            "SELECT * FROM sites WHERE name LIKE ? OR code LIKE ? ORDER BY km_from",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
    else:
        all_sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()
    db.close()

    sites_geo = [
        {
            "id": s["id"],
            "name": s["name"],
            "code": s["code"],
            "status": s["status"],
            "progress_pct": s["progress_pct"],
            "latitude": s["latitude"],
            "longitude": s["longitude"],
            "url": url_for("site_detail", site_id=s["id"]),
        }
        for s in all_sites if s["latitude"] is not None and s["longitude"] is not None
    ]
    return render_template("sites.html", sites=all_sites, sites_geo=sites_geo, q=q)


@app.route("/sites/<int:site_id>")
@login_required
def site_detail(site_id):
    db = get_db()
    site = db.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
    if not site:
        db.close()
        abort(404)

    workers = db.execute(
        "SELECT * FROM workers WHERE site_id=? AND active=1 ORDER BY name", (site_id,)
    ).fetchall()
    equipment = db.execute(
        """SELECT e.*, (e.operating_hours - e.hours_at_last_maint) as hours_since_maint
           FROM equipment e WHERE site_id=? ORDER BY name""",
        (site_id,),
    ).fetchall()
    stock = db.execute(
        """SELECT ms.*, m.name as material_name, m.unit, m.min_threshold
           FROM material_stock ms JOIN materials m ON m.id = ms.material_id
           WHERE ms.site_id=? ORDER BY m.name""",
        (site_id,),
    ).fetchall()
    today = date.today().isoformat()
    present_today = db.execute(
        "SELECT COUNT(*) c FROM attendance WHERE site_id=? AND date=? AND status='حاضر'",
        (site_id, today),
    ).fetchone()["c"]
    db.close()
    return render_template(
        "site_detail.html", site=site, workers=workers, equipment=equipment,
        stock=stock, present_today=present_today, today=today,
    )


@app.route("/sites/<int:site_id>/update", methods=["POST"])
@roles_required("admin", "manager")
def update_site(site_id):
    db = get_db()
    try:
        lat = request.form.get("latitude", "").strip()
        lng = request.form.get("longitude", "").strip()
        db.execute(
            """UPDATE sites SET progress_pct=?, budget=?, spent=?, status=?, manager_name=?,
                                 latitude=?, longitude=?
               WHERE id=?""",
            (
                float(request.form.get("progress_pct") or 0),
                float(request.form.get("budget") or 0),
                float(request.form.get("spent") or 0),
                request.form.get("status", "قيد التنفيذ"),
                request.form.get("manager_name", "").strip() or None,
                float(lat) if lat else None,
                float(lng) if lng else None,
                site_id,
            ),
        )
        log_activity(db, session.get("username"), f"تحديث بيانات الموقع رقم {site_id}", "sites")
        db.commit()
        flash("تم تحديث بيانات الموقع", "success")
    except Exception:
        db.rollback()
        flash("تعذّر تحديث بيانات الموقع", "error")
    db.close()
    return redirect(url_for("site_detail", site_id=site_id))


# ================================================================== العمالة
@app.route("/workers", methods=["GET", "POST"])
@login_required
def workers():
    db = get_db()
    if request.method == "POST":
        if session.get("role") not in ("admin", "manager"):
            flash("ليست لديك صلاحية إضافة عامل", "error")
            db.close()
            return redirect(url_for("workers"))
        try:
            name = request.form["name"].strip()
            if not name:
                raise ValueError("الاسم مطلوب")
            db.execute(
                """INSERT INTO workers (name, role, phone, national_id, daily_wage, site_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    name,
                    request.form.get("role", "").strip(),
                    request.form.get("phone", "").strip(),
                    request.form.get("national_id", "").strip(),
                    request.form.get("daily_wage") or 0,
                    request.form.get("site_id") or None,
                ),
            )
            log_activity(db, session.get("username"), f"إضافة عامل: {name}", "workers")
            db.commit()
            flash("تم إضافة العامل بنجاح", "success")
        except Exception:
            db.rollback()
            flash("تعذّرت إضافة العامل، تحقق من البيانات المدخلة", "error")
        db.close()
        return redirect(url_for("workers"))

    today = date.today().isoformat()
    q = request.args.get("q", "").strip()
    site_filter = request.args.get("site_id", "")

    query = """SELECT w.*, s.name as site_name,
                      a.status as today_status
               FROM workers w
               LEFT JOIN sites s ON s.id = w.site_id
               LEFT JOIN attendance a ON a.worker_id = w.id AND a.date = ?
               WHERE w.active = 1"""
    params = [today]
    if q:
        query += " AND (w.name LIKE ? OR w.role LIKE ? OR w.phone LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if site_filter:
        query += " AND w.site_id = ?"
        params.append(site_filter)
    query += " ORDER BY s.km_from, w.name"

    all_workers = db.execute(query, params).fetchall()
    all_sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()
    db.close()
    return render_template(
        "workers.html", workers=all_workers, sites=all_sites, today=today,
        q=q, site_filter=site_filter,
    )


@app.route("/workers/attendance", methods=["POST"])
@roles_required("admin", "manager")
def mark_attendance():
    db = get_db()
    try:
        worker_id = request.form["worker_id"]
        site_id = request.form["site_id"]
        status = request.form["status"]
        today = date.today().isoformat()
        check_in = request.form.get("check_in_time") or None
        overtime = request.form.get("overtime_hours") or 0

        db.execute(
            """INSERT INTO attendance (worker_id, site_id, date, status, check_in_time, overtime_hours)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(worker_id, date) DO UPDATE SET
                 status=excluded.status, site_id=excluded.site_id,
                 check_in_time=excluded.check_in_time, overtime_hours=excluded.overtime_hours""",
            (worker_id, site_id, today, status, check_in, overtime),
        )
        log_activity(db, session.get("username"), f"تسجيل حضور للعامل رقم {worker_id}: {status}", "workers")
        db.commit()
        flash("تم تسجيل الحضور", "success")
    except Exception:
        db.rollback()
        flash("تعذّر تسجيل الحضور", "error")
    db.close()
    return redirect(url_for("workers"))


# ================================================================== المعدات والأسطول
@app.route("/equipment", methods=["GET", "POST"])
@login_required
def equipment():
    db = get_db()
    if request.method == "POST":
        if session.get("role") not in ("admin", "manager"):
            flash("ليست لديك صلاحية تسجيل معدة", "error")
            db.close()
            return redirect(url_for("equipment"))
        try:
            name = request.form["name"].strip()
            code = request.form["code"].strip()
            if not name or not code:
                raise ValueError("بيانات ناقصة")
            db.execute(
                """INSERT INTO equipment (name, type, code, site_id, operating_hours,
                                           maintenance_interval, hours_at_last_maint,
                                           last_maintenance_date, status, fuel_cost_per_liter)
                   VALUES (?, ?, ?, ?, 0, ?, 0, ?, 'نشطة', ?)""",
                (
                    name,
                    request.form.get("type", "").strip(),
                    code,
                    request.form.get("site_id") or None,
                    request.form.get("maintenance_interval") or 250,
                    date.today().isoformat(),
                    request.form.get("fuel_cost_per_liter") or 0,
                ),
            )
            log_activity(db, session.get("username"), f"تسجيل معدة: {name} ({code})", "equipment")
            db.commit()
            flash("تم تسجيل المعدة بنجاح", "success")
        except Exception:
            db.rollback()
            flash("تعذّر تسجيل المعدة، تحقق أن الرمز غير مستخدم مسبقًا", "error")
        db.close()
        return redirect(url_for("equipment"))

    q = request.args.get("q", "").strip()
    query = """SELECT e.*, s.name as site_name,
                      (e.operating_hours - e.hours_at_last_maint) as hours_since_maint
               FROM equipment e LEFT JOIN sites s ON s.id = e.site_id"""
    params = []
    if q:
        query += " WHERE e.name LIKE ? OR e.code LIKE ? OR e.type LIKE ?"
        params = [f"%{q}%", f"%{q}%", f"%{q}%"]
    query += " ORDER BY e.name"
    all_equipment = db.execute(query, params).fetchall()
    all_sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()

    # إجمالي تكلفة الوقود لكل معدة
    fuel_costs = {}
    for row in db.execute(
        """SELECT equipment_id, SUM(fuel_liters) as total_liters
           FROM equipment_logs GROUP BY equipment_id"""
    ).fetchall():
        fuel_costs[row["equipment_id"]] = row["total_liters"] or 0

    db.close()
    return render_template(
        "equipment.html", equipment=all_equipment, sites=all_sites, q=q,
        fuel_costs=fuel_costs,
    )


@app.route("/equipment/<int:eq_id>/log", methods=["POST"])
@roles_required("admin", "manager")
def log_equipment(eq_id):
    db = get_db()
    try:
        log_type = request.form["log_type"]
        hours_used = float(request.form.get("hours_used") or 0)
        fuel_liters = float(request.form.get("fuel_liters") or 0)
        note = request.form.get("note", "").strip()
        today = date.today().isoformat()

        db.execute(
            """INSERT INTO equipment_logs (equipment_id, date, log_type, hours_used, fuel_liters, note)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (eq_id, today, log_type, hours_used, fuel_liters, note),
        )

        if log_type == "تشغيل":
            db.execute(
                "UPDATE equipment SET operating_hours = operating_hours + ? WHERE id = ?",
                (hours_used, eq_id),
            )
        elif log_type == "صيانة":
            eq = db.execute("SELECT operating_hours FROM equipment WHERE id=?", (eq_id,)).fetchone()
            db.execute(
                """UPDATE equipment SET status='نشطة', last_maintenance_date=?,
                                         hours_at_last_maint=? WHERE id=?""",
                (today, eq["operating_hours"], eq_id),
            )
        log_activity(db, session.get("username"), f"تسجيل حركة ({log_type}) للمعدة رقم {eq_id}", "equipment")
        db.commit()
        flash("تم تسجيل الحركة", "success")
    except Exception:
        db.rollback()
        flash("تعذّر تسجيل الحركة", "error")
    db.close()
    return redirect(url_for("equipment"))


@app.route("/equipment/<int:eq_id>/status", methods=["POST"])
@roles_required("admin", "manager")
def update_equipment_status(eq_id):
    db = get_db()
    try:
        db.execute(
            "UPDATE equipment SET status=?, site_id=? WHERE id=?",
            (request.form["status"], request.form.get("site_id") or None, eq_id),
        )
        log_activity(db, session.get("username"), f"تحديث حالة المعدة رقم {eq_id}", "equipment")
        db.commit()
        flash("تم تحديث حالة المعدة", "success")
    except Exception:
        db.rollback()
        flash("تعذّر تحديث حالة المعدة", "error")
    db.close()
    return redirect(url_for("equipment"))


# ================================================================== المواد والمخزون
@app.route("/materials", methods=["GET", "POST"])
@login_required
def materials():
    db = get_db()
    if request.method == "POST":
        if session.get("role") not in ("admin", "manager"):
            flash("ليست لديك صلاحية إضافة مادة", "error")
            db.close()
            return redirect(url_for("materials"))
        try:
            name = request.form["name"].strip()
            unit = request.form["unit"].strip()
            if not name or not unit:
                raise ValueError("بيانات ناقصة")
            db.execute(
                "INSERT INTO materials (name, unit, min_threshold, cost_per_unit) VALUES (?, ?, ?, ?)",
                (
                    name, unit,
                    request.form.get("min_threshold") or 0,
                    request.form.get("cost_per_unit") or 0,
                ),
            )
            log_activity(db, session.get("username"), f"إضافة مادة: {name}", "materials")
            db.commit()
            flash("تمت إضافة المادة بنجاح", "success")
        except Exception:
            db.rollback()
            flash("تعذّرت إضافة المادة", "error")
        db.close()
        return redirect(url_for("materials"))

    all_materials = db.execute("SELECT * FROM materials ORDER BY name").fetchall()
    all_sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()

    q = request.args.get("q", "").strip()
    stock_query = """SELECT ms.*, m.name as material_name, m.unit, m.min_threshold,
                             s.name as site_name
                      FROM material_stock ms
                      JOIN materials m ON m.id = ms.material_id
                      JOIN sites s ON s.id = ms.site_id"""
    params = []
    if q:
        stock_query += " WHERE m.name LIKE ? OR s.name LIKE ?"
        params = [f"%{q}%", f"%{q}%"]
    stock_query += " ORDER BY m.name, s.km_from"
    stock_rows = db.execute(stock_query, params).fetchall()

    transfers = db.execute(
        """SELECT t.*, m.name as material_name, m.unit,
                  sf.name as from_name, st.name as to_name
           FROM material_transfers t
           JOIN materials m ON m.id = t.material_id
           LEFT JOIN sites sf ON sf.id = t.from_site_id
           JOIN sites st ON st.id = t.to_site_id
           ORDER BY t.date DESC, t.id DESC LIMIT 20"""
    ).fetchall()

    total_stock_value = db.execute(
        """SELECT ROUND(SUM(ms.quantity * m.cost_per_unit), 0) as v
           FROM material_stock ms JOIN materials m ON m.id = ms.material_id"""
    ).fetchone()["v"] or 0

    db.close()
    return render_template(
        "materials.html",
        materials=all_materials,
        sites=all_sites,
        stock_rows=stock_rows,
        transfers=transfers,
        q=q,
        total_stock_value=total_stock_value,
    )


@app.route("/materials/stock", methods=["POST"])
@roles_required("admin", "manager")
def update_stock():
    db = get_db()
    try:
        material_id = request.form["material_id"]
        site_id = request.form["site_id"]
        quantity = float(request.form["quantity"])
        if quantity < 0:
            raise ValueError("الكمية لا يمكن أن تكون سالبة")

        db.execute(
            """INSERT INTO material_stock (material_id, site_id, quantity)
               VALUES (?, ?, ?)
               ON CONFLICT(material_id, site_id) DO UPDATE SET quantity=?""",
            (material_id, site_id, quantity, quantity),
        )
        log_activity(db, session.get("username"), f"تحديث رصيد مادة رقم {material_id} في موقع رقم {site_id}", "materials")
        db.commit()
        flash("تم تحديث الرصيد", "success")
    except Exception:
        db.rollback()
        flash("تعذّر تحديث الرصيد، تحقق من القيمة المدخلة", "error")
    db.close()
    return redirect(url_for("materials"))


@app.route("/materials/transfer", methods=["POST"])
@roles_required("admin", "manager")
def request_transfer():
    db = get_db()
    try:
        quantity = float(request.form["quantity"])
        if quantity <= 0:
            raise ValueError("الكمية يجب أن تكون أكبر من صفر")
        if request.form.get("from_site_id") == request.form.get("to_site_id"):
            raise ValueError("الموقع المصدر والوجهة متطابقان")
        db.execute(
            """INSERT INTO material_transfers (material_id, from_site_id, to_site_id,
                                                 quantity, date, status, note, requested_by)
               VALUES (?, ?, ?, ?, ?, 'قيد الانتظار', ?, ?)""",
            (
                request.form["material_id"],
                request.form.get("from_site_id") or None,
                request.form["to_site_id"],
                quantity,
                date.today().isoformat(),
                request.form.get("note", "").strip(),
                session.get("username"),
            ),
        )
        log_activity(db, session.get("username"), "طلب تحويل مادة جديد", "materials")
        db.commit()
        flash("تم إرسال طلب التحويل", "success")
    except Exception:
        db.rollback()
        flash("تعذّر إرسال طلب التحويل، تحقق من الكمية المدخلة", "error")
    db.close()
    return redirect(url_for("materials"))


@app.route("/materials/transfer/<int:transfer_id>/complete", methods=["POST"])
@roles_required("admin", "manager")
def complete_transfer(transfer_id):
    db = get_db()
    t = db.execute("SELECT * FROM material_transfers WHERE id=?", (transfer_id,)).fetchone()
    if t and t["status"] == "قيد الانتظار":
        if t["from_site_id"]:
            available = db.execute(
                "SELECT quantity FROM material_stock WHERE material_id=? AND site_id=?",
                (t["material_id"], t["from_site_id"]),
            ).fetchone()
            if not available or available["quantity"] < t["quantity"]:
                flash("لا يمكن تنفيذ التحويل: الرصيد غير كافٍ في الموقع المصدر", "error")
                db.close()
                return redirect(url_for("materials"))
            db.execute(
                """UPDATE material_stock SET quantity = quantity - ?
                   WHERE material_id=? AND site_id=?""",
                (t["quantity"], t["material_id"], t["from_site_id"]),
            )
        db.execute(
            """INSERT INTO material_stock (material_id, site_id, quantity)
               VALUES (?, ?, ?)
               ON CONFLICT(material_id, site_id) DO UPDATE SET quantity = quantity + ?""",
            (t["material_id"], t["to_site_id"], t["quantity"], t["quantity"]),
        )
        db.execute(
            "UPDATE material_transfers SET status='مكتمل' WHERE id=?", (transfer_id,)
        )
        log_activity(db, session.get("username"), f"تنفيذ طلب تحويل رقم {transfer_id}", "materials")
        db.commit()
        flash("تم تنفيذ التحويل وتحديث الأرصدة", "success")
    db.close()
    return redirect(url_for("materials"))


@app.route("/materials/transfer/<int:transfer_id>/reject", methods=["POST"])
@roles_required("admin", "manager")
def reject_transfer(transfer_id):
    db = get_db()
    t = db.execute("SELECT * FROM material_transfers WHERE id=?", (transfer_id,)).fetchone()
    if t and t["status"] == "قيد الانتظار":
        db.execute("UPDATE material_transfers SET status='مرفوض' WHERE id=?", (transfer_id,))
        log_activity(db, session.get("username"), f"رفض طلب تحويل رقم {transfer_id}", "materials")
        db.commit()
        flash("تم رفض طلب التحويل", "success")
    db.close()
    return redirect(url_for("materials"))


# ================================================================== التقارير والتصدير
@app.route("/reports")
@login_required
def reports():
    db = get_db()
    date_from = request.args.get("date_from") or (date.today() - timedelta(days=6)).isoformat()
    date_to = request.args.get("date_to") or date.today().isoformat()
    site_id = request.args.get("site_id", "")

    query = """SELECT w.name as worker_name, w.role, s.name as site_name,
                      a.date, a.status, a.check_in_time, a.overtime_hours
               FROM attendance a
               JOIN workers w ON w.id = a.worker_id
               JOIN sites s ON s.id = a.site_id
               WHERE a.date BETWEEN ? AND ?"""
    params = [date_from, date_to]
    if site_id:
        query += " AND a.site_id = ?"
        params.append(site_id)
    query += " ORDER BY a.date DESC, s.km_from"
    attendance_rows = db.execute(query, params).fetchall()

    summary = db.execute(
        """SELECT w.name as worker_name,
                  SUM(CASE WHEN a.status='حاضر' THEN 1 ELSE 0 END) as present_days,
                  SUM(CASE WHEN a.status='غائب' THEN 1 ELSE 0 END) as absent_days,
                  SUM(CASE WHEN a.status='إجازة' THEN 1 ELSE 0 END) as leave_days,
                  SUM(a.overtime_hours) as total_overtime,
                  w.daily_wage,
                  ROUND(SUM(CASE WHEN a.status='حاضر' THEN w.daily_wage ELSE 0 END), 2) as total_wage
           FROM attendance a
           JOIN workers w ON w.id = a.worker_id
           WHERE a.date BETWEEN ? AND ?
           GROUP BY w.id ORDER BY w.name""",
        (date_from, date_to),
    ).fetchall()

    all_sites = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()
    db.close()
    return render_template(
        "reports.html", attendance_rows=attendance_rows, summary=summary,
        sites=all_sites, date_from=date_from, date_to=date_to, site_id=site_id,
    )


def _build_csv(headers, rows):
    """ملف CSV بترميز UTF-8 مع BOM ليفتحه Excel بالعربية بشكل صحيح."""
    import csv
    text = io.StringIO()
    writer = csv.writer(text)
    writer.writerow([f"{APP_NAME_AR} — {APP_NAME_EN}"])
    writer.writerow(headers)
    writer.writerows(rows)
    buf = io.BytesIO(("\ufeff" + text.getvalue()).encode("utf-8"))
    buf.seek(0)
    return buf


@app.route("/export/<entity>")
@login_required
def export_entity(entity):
    db = get_db()
    today = date.today().isoformat()

    if entity == "workers":
        rows = db.execute(
            """SELECT w.name, w.role, w.phone, w.national_id, w.daily_wage,
                      s.name as site_name
               FROM workers w LEFT JOIN sites s ON s.id = w.site_id
               WHERE w.active=1 ORDER BY w.name"""
        ).fetchall()
        headers = ["الاسم", "الدور", "الهاتف", "الرقم الوطني", "الأجر اليومي", "الموقع"]
        data = [[r["name"], r["role"], r["phone"], r["national_id"], r["daily_wage"], r["site_name"]] for r in rows]
        filename = "قائمة_العمالة.csv"

    elif entity == "equipment":
        rows = db.execute(
            """SELECT e.name, e.type, e.code, e.status, s.name as site_name,
                      e.operating_hours, e.maintenance_interval,
                      (e.operating_hours - e.hours_at_last_maint) as hours_since_maint
               FROM equipment e LEFT JOIN sites s ON s.id = e.site_id ORDER BY e.name"""
        ).fetchall()
        headers = ["الاسم", "النوع", "الرمز", "الحالة", "الموقع", "ساعات التشغيل",
                   "دورة الصيانة", "ساعات منذ آخر صيانة"]
        data = [[r["name"], r["type"], r["code"], r["status"], r["site_name"],
                 r["operating_hours"], r["maintenance_interval"], round(r["hours_since_maint"] or 0, 1)] for r in rows]
        filename = "قائمة_المعدات.csv"

    elif entity == "materials":
        rows = db.execute(
            """SELECT m.name, m.unit, s.name as site_name, ms.quantity, m.min_threshold, m.cost_per_unit
               FROM material_stock ms
               JOIN materials m ON m.id = ms.material_id
               JOIN sites s ON s.id = ms.site_id
               ORDER BY m.name, s.km_from"""
        ).fetchall()
        headers = ["المادة", "الوحدة", "الموقع", "الرصيد", "الحد الأدنى", "التكلفة/الوحدة"]
        data = [[r["name"], r["unit"], r["site_name"], r["quantity"], r["min_threshold"], r["cost_per_unit"]] for r in rows]
        filename = "أرصدة_المواد.csv"

    elif entity == "sites":
        rows = db.execute("SELECT * FROM sites ORDER BY km_from").fetchall()
        headers = ["الاسم", "الرمز", "من كم", "إلى كم", "نسبة الإنجاز %", "الميزانية", "المصروف", "الحالة", "المدير"]
        data = [[r["name"], r["code"], r["km_from"], r["km_to"], r["progress_pct"],
                 r["budget"], r["spent"], r["status"], r["manager_name"]] for r in rows]
        filename = "المواقع_والقواطع.csv"

    elif entity == "attendance":
        date_from = request.args.get("date_from") or today
        date_to = request.args.get("date_to") or today
        rows = db.execute(
            """SELECT w.name as worker_name, s.name as site_name, a.date, a.status,
                      a.check_in_time, a.overtime_hours
               FROM attendance a
               JOIN workers w ON w.id = a.worker_id
               JOIN sites s ON s.id = a.site_id
               WHERE a.date BETWEEN ? AND ?
               ORDER BY a.date DESC""",
            (date_from, date_to),
        ).fetchall()
        headers = ["العامل", "الموقع", "التاريخ", "الحالة", "وقت الحضور", "ساعات إضافية"]
        data = [[r["worker_name"], r["site_name"], r["date"], r["status"], r["check_in_time"], r["overtime_hours"]] for r in rows]
        filename = "تقرير_الحضور.csv"

    else:
        db.close()
        abort(404)

    log_activity(db, session.get("username"), f"تصدير تقرير: {entity}", "reports")
    db.commit()
    db.close()

    buf = _build_csv(headers, data)
    return send_file(
        buf, as_attachment=True, download_name=filename,
        mimetype="text/csv; charset=utf-8",
    )


# ================================================================== سجل النشاط (للمدير فقط)
@app.route("/activity-log")
@roles_required("admin")
def activity_log_view():
    db = get_db()
    category = request.args.get("category", "")
    query = "SELECT * FROM activity_log"
    params = []
    if category:
        query += " WHERE category = ?"
        params.append(category)
    query += " ORDER BY id DESC LIMIT 200"
    logs = db.execute(query, params).fetchall()
    db.close()
    return render_template("activity_log.html", logs=logs, category=category)


# ================================================================== إدارة المستخدمين (للمدير فقط)
@app.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        try:
            username = request.form["username"].strip()
            full_name = request.form["full_name"].strip()
            password = request.form["password"]
            role = request.form.get("role", "viewer")
            if not username or not password or len(password) < 4:
                raise ValueError("بيانات غير صالحة")
            db.execute(
                "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), full_name, role),
            )
            log_activity(db, session.get("username"), f"إنشاء مستخدم جديد: {username}", "users")
            db.commit()
            flash("تم إنشاء المستخدم بنجاح", "success")
        except Exception:
            db.rollback()
            flash("تعذّر إنشاء المستخدم، تحقق أن اسم المستخدم غير مستخدم مسبقًا", "error")
        db.close()
        return redirect(url_for("users"))

    all_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    db.close()
    return render_template("users.html", users=all_users, role_labels=ROLE_LABELS)


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@roles_required("admin")
def toggle_user(user_id):
    db = get_db()
    if user_id == session.get("user_id"):
        flash("لا يمكنك تعطيل حسابك الخاص", "error")
        db.close()
        return redirect(url_for("users"))
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if user:
        new_state = 0 if user["active"] else 1
        db.execute("UPDATE users SET active=? WHERE id=?", (new_state, user_id))
        log_activity(db, session.get("username"), f"{'تفعيل' if new_state else 'تعطيل'} مستخدم: {user['username']}", "users")
        db.commit()
        flash("تم تحديث حالة المستخدم", "success")
    db.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
@roles_required("admin")
def change_user_password(user_id):
    global _default_pw_checked
    db = get_db()
    new_pw = request.form.get("new_password", "")
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash("المستخدم غير موجود", "error")
    elif len(new_pw) < 6:
        flash("كلمة المرور يجب ألا تقل عن 6 أحرف", "error")
    else:
        db.execute("UPDATE users SET password_hash=? WHERE id=?",
                   (generate_password_hash(new_pw), user_id))
        log_activity(db, session.get("username"), f"تغيير كلمة مرور المستخدم: {user['username']}", "users")
        db.commit()
        _default_pw_checked = False  # إعادة فحص الكلمات الافتراضية
        _check_default_passwords()
        flash(f"تم تغيير كلمة مرور {user['username']}", "success")
    db.close()
    return redirect(url_for("users"))


# ================================================================== فحص الحالة (للحملّالات وأنظمة المراقبة)
@app.route("/health")
def health():
    """نقطة فحص جاهزية الخدمة (لا تتطلب تسجيل دخول)."""
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db.close()
        return jsonify(status="ok", app=APP_NAME_EN), 200
    except Exception:
        app.logger.exception("فشل فحص الحالة")
        return jsonify(status="degraded"), 503


# ================================================================== رؤوس الأمان + سجل الطلبات
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data: blob: https://*.tile.openstreetmap.org; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'self'"
)


@app.after_request
def _security_headers(response):
    """رؤوس أمان أساسية + منع تخزين الصفحات المحمية في ذاكرة المتصفح + سجل الطلبات."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if ENABLE_CSP:
        response.headers.setdefault("Content-Security-Policy", CSP_POLICY)
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.endpoint != "static":
        response.headers.setdefault("Cache-Control", "private, no-store, max-age=0")
        app.logger.info("%s %s -> %s (%s)", request.method, request.path, response.status_code, _client_ip())
    return response


# ================================================================== صفحات الأخطاء بالعربية
@app.errorhandler(404)
def page_not_found(_error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(_error):
    app.logger.exception("خطأ داخلي غير معالج (500)")
    return render_template("errors/500.html"), 500


@app.errorhandler(413)
def payload_too_large(_error):
    flash("حجم البيانات المرسلة يتجاوز الحد المسموح (8MB)", "error")
    return redirect(_safe_next(request.referrer) or url_for("dashboard")), 413


# ================================================================== التشغيل
def _port_free(host, port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    # إن كان المنفذ مشغولًا نجرّب المنافذ التالية تلقائيًا
    for candidate in range(port, port + 20):
        if _port_free(host, candidate):
            port = candidate
            break
    ensure_db()
    shown = "127.0.0.1" if host in ("0.0.0.0", "") else host
    url = f"http://{shown}:{port}"
    print("=" * 60)
    print(f"  {APP_NAME_AR}")
    print(f"  افتح المتصفح على:  {url}")
    print("  لإيقاف الخادم اضغط Ctrl+C")
    print("=" * 60)
    app.logger.info("تشغيل الخادم على %s:%s", host, port)
    if _env_bool("OPEN_BROWSER", True) and not DEBUG:
        import threading, webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, debug=DEBUG, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
