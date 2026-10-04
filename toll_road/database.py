import sqlite3
import os
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "project_resources.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def get_db():
    """فتح اتصال بقاعدة البيانات بإعدادات مناسبة لبيئة الإنتاج
    (انتظار عند التعارض ومفاتيح خارجية)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(seed=True):
    """ينشئ قاعدة البيانات من الصفر وفق schema.sql، ويضيف بيانات تجريبية اختياريًا."""
    conn = get_db()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()

    if seed:
        _seed_demo_data(conn)

    conn.close()


def log_activity(db, username, action, category=None):
    """يسجّل حركة في سجل التدقيق (audit trail)."""
    db.execute(
        "INSERT INTO activity_log (username, action, category) VALUES (?, ?, ?)",
        (username, action, category),
    )


def _seed_demo_data(conn):
    cur = conn.cursor()

    # المستخدمون الافتراضيون
    users = [
        ("admin", "admin123", "مدير النظام", "admin"),
        ("manager", "manager123", "مشرف المشروع", "manager"),
        ("viewer", "viewer123", "مستخدم اطلاع فقط", "viewer"),
    ]
    for username, pwd, full_name, role in users:
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(pwd), full_name, role),
        )
    conn.commit()

    # المواقع / القواطع
    sites = [
        ("القاطع الشرقي", "E-01", 0, 50, 62, 4200000, 2650000, "محمد الشريف", "قيد التنفيذ", 32.0836, 20.0864),
        ("القاطع الأوسط", "M-02", 50, 210, 38, 9600000, 3100000, "خالد الفيتوري", "قيد التنفيذ", 31.1370, 19.1746),
        ("القاطع الغربي", "W-03", 210, 390, 15, 8100000, 900000, "مفتاح الورفلي", "قيد التنفيذ", 30.6409, 17.6198),
    ]
    cur.executemany(
        """INSERT INTO sites (name, code, km_from, km_to, progress_pct, budget, spent,
                               manager_name, status, latitude, longitude)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        sites,
    )
    conn.commit()
    site_ids = [r["id"] for r in cur.execute("SELECT id FROM sites ORDER BY id")]

    # العمالة
    workers = [
        ("محمد الشريف", "مهندس موقع", "0910000001", "119850001", 120, site_ids[0]),
        ("عائشة المبروك", "مساح", "0910000002", "119850002", 90, site_ids[0]),
        ("خالد الفيتوري", "سائق شاحنة", "0910000003", "119850003", 70, site_ids[1]),
        ("سالم القذافي", "فني رصف", "0910000004", "119850004", 65, site_ids[1]),
        ("مفتاح الورفلي", "مشرف عمال", "0910000005", "119850005", 100, site_ids[2]),
        ("نورية السنوسي", "مهندسة جودة", "0910000006", "119850006", 110, site_ids[2]),
        ("عبدالسلام رمضان", "عامل عام", "0910000007", "119850007", 55, site_ids[1]),
        ("فاطمة الزروق", "إدارية موقع", "0910000008", "119850008", 60, site_ids[0]),
    ]
    cur.executemany(
        "INSERT INTO workers (name, role, phone, national_id, daily_wage, site_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        workers,
    )
    conn.commit()
    worker_rows = cur.execute("SELECT id, site_id FROM workers").fetchall()

    today = date.today()
    # حضور آخر 7 أيام لبيانات رسم بياني ذات معنى
    for day_offset in range(6, -1, -1):
        d = (today - timedelta(days=day_offset)).isoformat()
        for i, w in enumerate(worker_rows):
            status = "حاضر"
            if day_offset == 0 and i == 2:
                status = "غائب"
            elif day_offset == 3 and i == 6:
                status = "إجازة"
            elif (i + day_offset) % 7 == 0 and day_offset != 0:
                status = "غائب"
            try:
                cur.execute(
                    "INSERT INTO attendance (worker_id, site_id, date, status, check_in_time, overtime_hours) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (w["id"], w["site_id"], d, status, "07:00" if status == "حاضر" else None,
                     2 if (i == 0 and day_offset == 1) else 0),
                )
            except sqlite3.IntegrityError:
                pass
    conn.commit()

    # المعدات
    equipment = [
        ("حفارة كاتربيلر 320", "حفارة", "EQ-101", site_ids[0], 1180, 250, 1000, 3.2),
        ("شاحنة قلابة فولفو", "شاحنة نقل", "EQ-102", site_ids[0], 3400, 300, 3200, 3.0),
        ("جريدر كوماتسو", "جريدر", "EQ-103", site_ids[1], 860, 250, 620, 3.4),
        ("مدحلة دينابك", "مدحلة", "EQ-104", site_ids[1], 240, 250, 0, 2.9),
        ("لودر جون دير", "لودر", "EQ-105", site_ids[2], 1990, 250, 1770, 3.1),
    ]
    for name, etype, code, site_id, hours, interval, last_hours, fuel_cost in equipment:
        cur.execute(
            "INSERT INTO equipment (name, type, code, site_id, operating_hours, "
            "maintenance_interval, hours_at_last_maint, last_maintenance_date, status, fuel_cost_per_liter) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name, etype, code, site_id, hours, interval, last_hours,
                (today - timedelta(days=20)).isoformat(), "نشطة", fuel_cost,
            ),
        )
    conn.commit()
    eq_ids = [r["id"] for r in cur.execute("SELECT id FROM equipment ORDER BY id")]
    cur.execute(
        "INSERT INTO equipment_logs (equipment_id, date, log_type, hours_used, fuel_liters, note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (eq_ids[0], today.isoformat(), "تشغيل", 8, 65, "حفر أساسات - كم 12"),
    )
    conn.commit()

    # المواد
    materials = [
        ("أسفلت MCO", "طن", 50, 610),
        ("إسمنت", "طن", 30, 320),
        ("حصى مكسر", "م3", 100, 45),
        ("ديزل", "لتر", 500, 2.1),
    ]
    cur.executemany(
        "INSERT INTO materials (name, unit, min_threshold, cost_per_unit) VALUES (?, ?, ?, ?)",
        materials,
    )
    conn.commit()
    mat_ids = [r["id"] for r in cur.execute("SELECT id FROM materials ORDER BY id")]

    stock = [
        (mat_ids[0], site_ids[0], 120),
        (mat_ids[0], site_ids[1], 35),   # تحت الحد الأدنى
        (mat_ids[0], site_ids[2], 80),
        (mat_ids[1], site_ids[0], 60),
        (mat_ids[1], site_ids[1], 25),   # تحت الحد الأدنى
        (mat_ids[2], site_ids[2], 210),
        (mat_ids[3], site_ids[0], 900),
        (mat_ids[3], site_ids[1], 300),  # تحت الحد الأدنى
    ]
    cur.executemany(
        "INSERT INTO material_stock (material_id, site_id, quantity) VALUES (?, ?, ?)",
        stock,
    )
    conn.commit()

    cur.execute(
        "INSERT INTO material_transfers (material_id, from_site_id, to_site_id, "
        "quantity, date, status, note, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (mat_ids[0], site_ids[0], site_ids[1], 20, today.isoformat(), "قيد الانتظار",
         "نقص أسفلت في القاطع الأوسط", "manager"),
    )
    conn.commit()

    log_activity(cur, "system", "تهيئة النظام وتحميل البيانات التجريبية", "system")
    conn.commit()


if __name__ == "__main__":
    init_db(seed=True)
    print("تم إنشاء قاعدة البيانات وتعبئتها ببيانات تجريبية:", DB_PATH)
