-- ==========================================================
-- إدارة خدمات الطريق الدولي — Toll Road Services Management
-- (عمالة + معدات + مواد + مستخدمون + سجل نشاط) موحّدة حول "المواقع/القواطع"
-- الإصدار 2 — نسخة موسّعة بميزات احترافية وجاهزة للإنتاج
-- ==========================================================

DROP TABLE IF EXISTS activity_log;
DROP TABLE IF EXISTS material_transfers;
DROP TABLE IF EXISTS material_stock;
DROP TABLE IF EXISTS materials;
DROP TABLE IF EXISTS equipment_logs;
DROP TABLE IF EXISTS equipment;
DROP TABLE IF EXISTS attendance;
DROP TABLE IF EXISTS workers;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS users;

-- المستخدمون (تسجيل الدخول + الصلاحيات)
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'viewer',   -- admin | manager | viewer
    active          INTEGER DEFAULT 1,
    created_at      TEXT DEFAULT (datetime('now'))
);

-- المواقع / القواطع (العمود الفقري الذي يربط كل شيء)
CREATE TABLE sites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    code            TEXT NOT NULL UNIQUE,
    km_from         REAL,
    km_to           REAL,
    progress_pct    REAL DEFAULT 0,      -- نسبة الإنجاز الفعلي
    budget          REAL DEFAULT 0,      -- الميزانية المعتمدة
    spent           REAL DEFAULT 0,      -- المصروف الفعلي
    manager_name    TEXT,                -- مدير الموقع المسؤول
    latitude        REAL,                -- إحداثيات الموقع (لخريطة الموقع)
    longitude       REAL,
    status          TEXT NOT NULL DEFAULT 'قيد التنفيذ',  -- قيد التنفيذ | متوقف | مكتمل
    created_at      TEXT DEFAULT (datetime('now'))
);

-- العمالة
CREATE TABLE workers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    role        TEXT,
    phone       TEXT,
    national_id TEXT,
    daily_wage  REAL DEFAULT 0,
    site_id     INTEGER,
    active      INTEGER DEFAULT 1,
    FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- الحضور اليومي
CREATE TABLE attendance (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id       INTEGER NOT NULL,
    site_id         INTEGER NOT NULL,
    date            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'حاضر',
    check_in_time   TEXT,
    overtime_hours  REAL DEFAULT 0,
    UNIQUE(worker_id, date),
    FOREIGN KEY (worker_id) REFERENCES workers(id),
    FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- المعدات والأسطول
CREATE TABLE equipment (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT NOT NULL,
    type                    TEXT,
    code                    TEXT NOT NULL UNIQUE,
    status                  TEXT NOT NULL DEFAULT 'نشطة',
    site_id                 INTEGER,
    operating_hours         REAL DEFAULT 0,
    last_maintenance_date   TEXT,
    maintenance_interval    REAL DEFAULT 250,
    hours_at_last_maint     REAL DEFAULT 0,
    fuel_cost_per_liter     REAL DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- سجلات تشغيل/صيانة المعدات
CREATE TABLE equipment_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    equipment_id    INTEGER NOT NULL,
    date            TEXT NOT NULL,
    log_type        TEXT NOT NULL,
    hours_used      REAL DEFAULT 0,
    fuel_liters     REAL DEFAULT 0,
    note            TEXT,
    FOREIGN KEY (equipment_id) REFERENCES equipment(id)
);

-- المواد (الأصناف)
CREATE TABLE materials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    unit            TEXT NOT NULL,
    min_threshold   REAL DEFAULT 0,
    cost_per_unit   REAL DEFAULT 0
);

-- رصيد كل مادة في كل موقع
CREATE TABLE material_stock (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id     INTEGER NOT NULL,
    site_id         INTEGER NOT NULL,
    quantity        REAL DEFAULT 0,
    UNIQUE(material_id, site_id),
    FOREIGN KEY (material_id) REFERENCES materials(id),
    FOREIGN KEY (site_id) REFERENCES sites(id)
);

-- طلبات تحويل المواد بين المواقع
CREATE TABLE material_transfers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id     INTEGER NOT NULL,
    from_site_id    INTEGER,
    to_site_id      INTEGER NOT NULL,
    quantity        REAL NOT NULL,
    date            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'قيد الانتظار',  -- قيد الانتظار | مكتمل | مرفوض
    note            TEXT,
    requested_by    TEXT,
    FOREIGN KEY (material_id) REFERENCES materials(id),
    FOREIGN KEY (from_site_id) REFERENCES sites(id),
    FOREIGN KEY (to_site_id) REFERENCES sites(id)
);

-- سجل النشاط (تدقيق / Audit Trail)
CREATE TABLE activity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT,
    action      TEXT NOT NULL,      -- وصف مختصر للعملية
    category    TEXT,               -- sites | workers | equipment | materials | auth
    created_at  TEXT DEFAULT (datetime('now'))
);
