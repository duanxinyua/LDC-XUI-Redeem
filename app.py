#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
3x-ui 兑换码系统
用户通过兑换码或 LINUX DO Credit 积分获取节点订阅链接
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps

import requests
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# 数据库路径
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'redeem.db')
LOCAL_TIME_OFFSET = timedelta(hours=8)


def local_now():
    """返回本地北京时间。"""
    return datetime.utcnow() + LOCAL_TIME_OFFSET


def format_dt(value):
    """统一格式化数据库时间。"""
    if not value:
        return '-'
    text = str(value).strip()
    return text[:16] if text else '-'


def get_csrf_token():
    """获取当前会话的 CSRF Token。"""
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def verify_csrf_token():
    """校验后台写操作的 CSRF Token。"""
    expected = session.get('_csrf_token')
    supplied = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
    if not expected or not supplied:
        return False
    return secrets.compare_digest(str(expected), str(supplied))


def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not verify_csrf_token():
            return jsonify({'success': False, 'msg': '页面已过期，请刷新后重试'}), 400
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_csrf_token()}


def legacy_password_hash(password):
    """兼容旧版 SHA-256 密码。"""
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password):
    """生成带盐密码哈希。"""
    return generate_password_hash(password)


def verify_password(stored_hash, password):
    """校验密码，并兼容旧版 SHA-256 哈希。"""
    if not stored_hash:
        return False
    if len(stored_hash) == 64 and all(ch in string.hexdigits for ch in stored_hash):
        return secrets.compare_digest(stored_hash, legacy_password_hash(password))
    try:
        return check_password_hash(stored_hash, password)
    except ValueError:
        return False


def env_int(name, default, min_value=1):
    """读取整数环境变量。"""
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(min_value, value)


# 3x-ui 配置
XUI_CONFIG = {
    'host': os.getenv('XUI_HOST', 'http://127.0.0.1:2053').strip().rstrip('/'),
    'username': os.getenv('XUI_USERNAME', '').strip(),
    'password': os.getenv('XUI_PASSWORD', '').strip(),
    'session_cookie': None,
    'expire_days': env_int('XUI_EXPIRE_DAYS', 30),
    'traffic_limit': env_int('XUI_TRAFFIC_LIMIT', 20),
}
if not XUI_CONFIG['host']:
    XUI_CONFIG['host'] = 'http://127.0.0.1:2053'

# 3x-ui 不可用时的兜底入站。开源版本默认不内置任何真实节点。
# 正常使用时请在后台配置 3x-ui 面板，系统会实时读取 vmess/ws 入站。
DEFAULT_INBOUNDS = {}
INBOUNDS = DEFAULT_INBOUNDS

# 订阅配置
SUB_CONFIG = {
    'domain': os.getenv('NODE_DOMAIN', os.getenv('SUB_DOMAIN', 'example.com')).strip() or 'example.com',
    'sub_domain': os.getenv('SUB_DOMAIN', 'example.com').strip() or 'example.com',
    'port': env_int('SUB_PORT', 443),
    'protocol': os.getenv('SUB_PROTOCOL', 'vmess').strip() or 'vmess',
    'security': os.getenv('SUB_SECURITY', 'tls').strip() or 'tls',
    'network': os.getenv('SUB_NETWORK', 'ws').strip() or 'ws',
}
PUBLIC_BASE_URL = os.getenv('PUBLIC_BASE_URL', f"https://{SUB_CONFIG['sub_domain']}").rstrip('/')

# LDC 配置
LDC_CONFIG = {
    'gateway': os.getenv('LDC_GATEWAY', 'https://credit.linux.do/epay').rstrip('/'),
    'pid': os.getenv('LDC_PID', '').strip(),
    'key': os.getenv('LDC_KEY', '').strip(),
    'min_traffic': max(1, int(os.getenv('LDC_MIN_TRAFFIC', '1'))),
    'max_traffic': max(1, int(os.getenv('LDC_MAX_TRAFFIC', '200'))),
}
if LDC_CONFIG['max_traffic'] < LDC_CONFIG['min_traffic']:
    LDC_CONFIG['max_traffic'] = LDC_CONFIG['min_traffic']
LDC_PENDING_EXPIRE_MINUTES = 10

APP_SETTINGS_DEFAULTS = {
    'xui_host': XUI_CONFIG['host'],
    'xui_username': XUI_CONFIG['username'],
    'xui_password': XUI_CONFIG['password'],
    'xui_expire_days': str(XUI_CONFIG['expire_days']),
    'xui_traffic_limit': str(XUI_CONFIG['traffic_limit']),
    'xui_enabled_inbounds': '',
    'xui_enabled_nodes': '',
    'ldc_enabled': '1' if LDC_CONFIG['pid'] and LDC_CONFIG['key'] else '0',
    'ldc_total_limit_gb': '0',
    'ldc_exchange_ratio': '1',
    'turnstile_enabled': '1' if os.getenv('TURNSTILE_SITE_KEY') and os.getenv('TURNSTILE_SECRET_KEY') else '0',
    'turnstile_site_key': os.getenv('TURNSTILE_SITE_KEY', '').strip(),
    'turnstile_secret_key': os.getenv('TURNSTILE_SECRET_KEY', '').strip(),
}


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redeem_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code VARCHAR(32) UNIQUE NOT NULL,
            traffic_limit INTEGER DEFAULT 20,
            expire_days INTEGER DEFAULT 30,
            inbound_id INTEGER DEFAULT NULL,
            used INTEGER DEFAULT 0,
            used_by VARCHAR(64),
            used_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(64) DEFAULT 'admin'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid VARCHAR(36) UNIQUE NOT NULL,
            email VARCHAR(128),
            inbound_id INTEGER DEFAULT NULL,
            traffic_used INTEGER DEFAULT 0,
            traffic_limit INTEGER,
            expire_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            redeem_code VARCHAR(32)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(64) UNIQUE NOT NULL,
            password VARCHAR(128) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ldc_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            out_trade_no VARCHAR(64) UNIQUE NOT NULL,
            trade_no VARCHAR(64),
            order_name VARCHAR(64) NOT NULL,
            inbound_id INTEGER NOT NULL,
            traffic_gb INTEGER NOT NULL,
            expire_days INTEGER NOT NULL,
            amount VARCHAR(16) NOT NULL,
            status VARCHAR(16) DEFAULT 'pending',
            user_uuid VARCHAR(36),
            user_email VARCHAR(128),
            paid_at DATETIME,
            completed_at DATETIME,
            notify_payload TEXT,
            error_message TEXT,
            refund_status VARCHAR(16),
            refund_at DATETIME,
            refund_payload TEXT,
            refund_message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ldc_api_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action VARCHAR(32) NOT NULL,
            out_trade_no VARCHAR(64),
            trade_no VARCHAR(64),
            request_payload TEXT,
            response_payload TEXT,
            success INTEGER DEFAULT 0,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key VARCHAR(64) PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS xui_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(64) NOT NULL,
            host TEXT NOT NULL,
            username VARCHAR(64) NOT NULL,
            password TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            sort_order INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute("PRAGMA table_info(ldc_orders)")
    ldc_order_columns = {row['name'] for row in cursor.fetchall()}
    ldc_order_migrations = {
        'refund_status': "ALTER TABLE ldc_orders ADD COLUMN refund_status VARCHAR(16)",
        'refund_at': "ALTER TABLE ldc_orders ADD COLUMN refund_at DATETIME",
        'refund_payload': "ALTER TABLE ldc_orders ADD COLUMN refund_payload TEXT",
        'refund_message': "ALTER TABLE ldc_orders ADD COLUMN refund_message TEXT",
    }
    for column, sql in ldc_order_migrations.items():
        if column not in ldc_order_columns:
            cursor.execute(sql)

    table_migrations = {
        'redeem_codes': {
            'xui_instance_id': "ALTER TABLE redeem_codes ADD COLUMN xui_instance_id INTEGER",
        },
        'users': {
            'xui_instance_id': "ALTER TABLE users ADD COLUMN xui_instance_id INTEGER",
        },
        'ldc_orders': {
            'xui_instance_id': "ALTER TABLE ldc_orders ADD COLUMN xui_instance_id INTEGER",
        },
    }
    for table_name, migrations in table_migrations.items():
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = {row['name'] for row in cursor.fetchall()}
        for column, sql in migrations.items():
            if column not in columns:
                cursor.execute(sql)

    for key, value in APP_SETTINGS_DEFAULTS.items():
        cursor.execute('''
            INSERT OR IGNORE INTO app_settings (key, value)
            VALUES (?, ?)
        ''', (key, value))

    cursor.execute("SELECT key, value FROM app_settings")
    settings = dict(APP_SETTINGS_DEFAULTS)
    settings.update({row['key']: row['value'] for row in cursor.fetchall()})

    cursor.execute("SELECT COUNT(*) AS total FROM xui_instances")
    if cursor.fetchone()['total'] == 0:
        cursor.execute('''
            INSERT INTO xui_instances (
                name, host, username, password, enabled, sort_order, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, 1, ?, ?)
        ''', (
            '默认 3x-ui',
            (settings.get('xui_host') or XUI_CONFIG['host'] or 'http://127.0.0.1:2053').strip().rstrip('/'),
            (settings.get('xui_username') or '').strip(),
            settings.get('xui_password') or '',
            local_now(),
            local_now()
        ))

    cursor.execute("SELECT id FROM xui_instances ORDER BY sort_order ASC, id ASC LIMIT 1")
    default_xui_instance = cursor.fetchone()
    default_xui_instance_id = int(default_xui_instance['id']) if default_xui_instance else 1

    for table_name in ('redeem_codes', 'users', 'ldc_orders'):
        cursor.execute(
            f"UPDATE {table_name} SET xui_instance_id = ? WHERE xui_instance_id IS NULL",
            (default_xui_instance_id,)
        )

    if not (settings.get('xui_enabled_nodes') or '').strip() and (settings.get('xui_enabled_inbounds') or '').strip():
        legacy_node_keys = []
        for item in str(settings.get('xui_enabled_inbounds') or '').split(','):
            item = item.strip()
            if item.isdigit() and int(item) > 0:
                legacy_node_keys.append(f"{default_xui_instance_id}:{int(item)}")
        if legacy_node_keys:
            cursor.execute('''
                INSERT INTO app_settings (key, value, updated_at)
                VALUES ('xui_enabled_nodes', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
            ''', (','.join(legacy_node_keys),))

    cursor.execute("SELECT COUNT(*) AS total FROM admins")
    if cursor.fetchone()['total'] == 0:
        initial_admin_username = os.getenv('ADMIN_USERNAME', 'admin').strip() or 'admin'
        initial_admin_password = os.getenv('ADMIN_PASSWORD', 'admin')
        password_hash = hash_password(initial_admin_password)
        cursor.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            (initial_admin_username, password_hash)
        )

    conn.commit()
    conn.close()


def generate_code(length=24):
    """生成随机兑换码"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_uuid():
    """生成标准格式 UUID"""
    import uuid
    return str(uuid.uuid4())


def generate_order_no():
    """生成 LDC 订单号"""
    return f"LDC{local_now().strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"


def copy_inbounds(inbounds):
    """复制入站字典，避免调用方误改全局兜底配置。"""
    return {int(inbound_id): dict(config) for inbound_id, config in inbounds.items()}


def parse_inbound_id_list(value):
    """解析逗号分隔的入站 ID 列表。"""
    inbound_ids = set()
    for item in str(value or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            inbound_id = int(item)
        except ValueError:
            continue
        if inbound_id > 0:
            inbound_ids.add(inbound_id)
    return inbound_ids


def row_get(row, key, default=None):
    """兼容 sqlite3.Row 和 dict 的安全取值。"""
    if row is None:
        return default
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        value = default
    return default if value is None else value


def make_node_key(xui_instance_id, inbound_id):
    """生成全局唯一节点标识，避免多个 3x-ui 的入站 ID 冲突。"""
    try:
        instance_id = int(xui_instance_id)
    except (TypeError, ValueError):
        instance_id = 1
    try:
        node_id = int(inbound_id)
    except (TypeError, ValueError):
        node_id = 14
    return f"{instance_id}:{node_id}"


def parse_node_key_list(value, default_instance_id=1):
    """解析复合节点白名单，兼容旧版仅入站 ID 的配置。"""
    node_keys = set()
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value or '').split(',')

    for item in items:
        text = str(item or '').strip()
        if not text:
            continue
        if ':' in text:
            left, right = text.split(':', 1)
        else:
            left, right = str(default_instance_id), text
        try:
            instance_id = int(left)
            inbound_id = int(right)
        except (TypeError, ValueError):
            continue
        if instance_id > 0 and inbound_id > 0:
            node_keys.add(make_node_key(instance_id, inbound_id))
    return node_keys


def normalize_xui_instance(row):
    """将 3x-ui 面板记录转成普通 dict，方便模板和 API 使用。"""
    instance_id = parse_int(row_get(row, 'id'), 1)
    name = str(row_get(row, 'name', '') or '').strip() or f'3x-ui #{instance_id}'
    host = str(row_get(row, 'host', '') or '').strip().rstrip('/')
    username = str(row_get(row, 'username', '') or '').strip()
    password = row_get(row, 'password', '') or ''
    enabled = parse_bool(row_get(row, 'enabled', 1), True)
    return {
        'id': instance_id,
        'name': name,
        'host': host or 'http://127.0.0.1:2053',
        'username': username,
        'password': password,
        'enabled': enabled,
        'sort_order': parse_int(row_get(row, 'sort_order'), instance_id),
        'password_set': bool(password),
        'configured': bool(host and username and password),
    }


def get_xui_instances(conn=None, include_disabled=False):
    """读取 3x-ui 面板列表。"""
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True

    cursor = conn.cursor()
    try:
        if include_disabled:
            cursor.execute("SELECT * FROM xui_instances ORDER BY sort_order ASC, id ASC")
        else:
            cursor.execute("SELECT * FROM xui_instances WHERE enabled = 1 ORDER BY sort_order ASC, id ASC")
        instances = [normalize_xui_instance(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        instances = []

    if close_conn:
        conn.close()

    return instances


def get_default_xui_instance(conn=None):
    """获取默认 3x-ui 面板；没有新表数据时回落到旧配置。"""
    instances = get_xui_instances(conn, include_disabled=True)
    if instances:
        enabled_instances = [instance for instance in instances if instance['enabled']]
        return enabled_instances[0] if enabled_instances else instances[0]

    settings = load_app_settings(conn)
    return {
        'id': 1,
        'name': '默认 3x-ui',
        'host': (settings.get('xui_host') or XUI_CONFIG['host'] or 'http://127.0.0.1:2053').strip().rstrip('/'),
        'username': (settings.get('xui_username') or '').strip(),
        'password': settings.get('xui_password') or '',
        'enabled': True,
        'sort_order': 1,
        'password_set': bool(settings.get('xui_password')),
        'configured': bool((settings.get('xui_host') or XUI_CONFIG['host']) and settings.get('xui_username') and settings.get('xui_password')),
    }


def get_xui_instance(xui_instance_id=None, conn=None):
    """按 ID 获取 3x-ui 面板，查不到时返回默认面板。"""
    try:
        instance_id = int(xui_instance_id)
    except (TypeError, ValueError):
        instance_id = None

    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True

    instance = None
    if instance_id:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM xui_instances WHERE id = ?", (instance_id,))
            row = cursor.fetchone()
            if row:
                instance = normalize_xui_instance(row)
        except sqlite3.OperationalError:
            instance = None

    if instance is None:
        instance = get_default_xui_instance(conn)

    if close_conn:
        conn.close()

    return instance


def decorate_inbound_config(inbound_config, instance):
    """给入站配置补充所属 3x-ui 面板信息。"""
    config = dict(inbound_config)
    inbound_id = parse_int(config.get('id') or config.get('inbound_id'), 14)
    instance_id = parse_int(instance.get('id'), 1)
    instance_name = instance.get('name') or f'3x-ui #{instance_id}'
    node_name = config.get('name') or f'节点{inbound_id}'
    config.update({
        'id': inbound_id,
        'inbound_id': inbound_id,
        'xui_instance_id': instance_id,
        'xui_instance_name': instance_name,
        'node_key': make_node_key(instance_id, inbound_id),
        'display_name': f"{instance_name} · {node_name}",
    })
    return config


def default_inbounds_for_instance(instance=None):
    """生成默认兜底入站，绑定到指定 3x-ui 面板。"""
    instance = instance or get_default_xui_instance()
    decorated = {}
    for inbound_id, config in DEFAULT_INBOUNDS.items():
        node = decorate_inbound_config({'id': inbound_id, **config}, instance)
        decorated[node['node_key']] = node
    return decorated


def parse_xui_inbound_config(inbound_obj):
    """解析 3x-ui 返回的单个入站配置。"""
    if not inbound_obj:
        return None

    inbound_id = parse_int(inbound_obj.get('id'), 0)
    if inbound_id <= 0:
        return None

    stream_settings = inbound_obj.get('streamSettings') or {}
    if isinstance(stream_settings, str):
        try:
            stream_settings = json.loads(stream_settings)
        except Exception:
            stream_settings = {}
    if not isinstance(stream_settings, dict):
        stream_settings = {}

    ws_settings = stream_settings.get('wsSettings') or {}
    if not isinstance(ws_settings, dict):
        ws_settings = {}

    remark = str(inbound_obj.get('remark') or '').strip()
    name = remark or f'节点{inbound_id}'
    protocol = str(inbound_obj.get('protocol') or '').strip().lower()
    network = str(stream_settings.get('network') or '').strip().lower()
    security = str(stream_settings.get('security') or '').strip().lower()

    return {
        'id': inbound_id,
        'name': name,
        'port': parse_int(inbound_obj.get('port'), 0),
        'protocol': protocol,
        'network': network,
        'security': security,
        'ws_path': str(ws_settings.get('path') or '').strip(),
        'host': str(ws_settings.get('host') or '').strip(),
        'enable': parse_bool(inbound_obj.get('enable'), False),
    }


def fetch_xui_inbounds(include_disabled=False, instance=None):
    """从指定 3x-ui 读取 vmess/ws 入站，可用于后台上架选择。"""
    client = XUIClient(instance=instance)
    if not client.login():
        return None

    inbound_list = client.list_inbounds()
    if not inbound_list or not inbound_list.get('success'):
        return None

    instance = client.instance or get_default_xui_instance()
    inbounds = {}
    for inbound_obj in inbound_list.get('obj') or []:
        parsed = parse_xui_inbound_config(inbound_obj)
        if not parsed:
            continue
        if parsed['protocol'] != 'vmess' or parsed['network'] != 'ws':
            continue
        if not include_disabled and not parsed['enable']:
            continue
        node = decorate_inbound_config(parsed, instance)
        inbounds[node['node_key']] = node

    return dict(sorted(inbounds.items(), key=lambda item: (item[1]['xui_instance_id'], item[1]['id'])))


def fetch_all_xui_inbounds(include_disabled=False, include_disabled_instances=False):
    """从所有已配置的 3x-ui 面板读取入站。"""
    instances = get_xui_instances(include_disabled=include_disabled_instances)
    instances = [instance for instance in instances if instance['configured'] and (include_disabled_instances or instance['enabled'])]
    if not instances:
        if get_xui_instances(include_disabled=True):
            return {}
        default_instance = get_default_xui_instance()
        return default_inbounds_for_instance(default_instance)

    all_inbounds = {}
    for instance in instances:
        inbounds = fetch_xui_inbounds(include_disabled=include_disabled, instance=instance)
        if inbounds:
            all_inbounds.update(inbounds)

    if not all_inbounds:
        all_inbounds = default_inbounds_for_instance(instances[0])

    return dict(sorted(all_inbounds.items(), key=lambda item: (item[1]['xui_instance_id'], item[1]['id'])))


def get_available_inbounds():
    """从所有 3x-ui 实时读取可用入站列表。"""
    inbounds = fetch_all_xui_inbounds()
    if not inbounds:
        if get_xui_instances(include_disabled=True):
            return {}
        inbounds = default_inbounds_for_instance()

    settings = load_app_settings()
    default_instance = get_default_xui_instance()
    enabled_node_keys = parse_node_key_list(settings.get('xui_enabled_nodes'), default_instance_id=default_instance['id'])
    if not enabled_node_keys:
        return inbounds

    return {
        node_key: config
        for node_key, config in inbounds.items()
        if node_key in enabled_node_keys
    }


def get_live_inbound_config(inbound_id, inbounds=None, xui_instance_id=None):
    """实时获取指定入站配置，用于生成已绑定用户的订阅。"""
    try:
        inbound_id = int(inbound_id)
    except (TypeError, ValueError):
        inbound_id = 14
    instance = get_xui_instance(xui_instance_id)
    node_key = make_node_key(instance['id'], inbound_id)

    catalog = inbounds or {}
    if node_key in catalog:
        return catalog[node_key]

    client = XUIClient(instance=instance)
    if not client.login():
        return get_inbound_config(inbound_id, default_inbounds_for_instance(instance), xui_instance_id=instance['id'])

    inbound = client.get_inbound(inbound_id)
    if not inbound or not inbound.get('success'):
        return get_inbound_config(inbound_id, default_inbounds_for_instance(instance), xui_instance_id=instance['id'])

    parsed = parse_xui_inbound_config(inbound.get('obj'))
    if parsed and parsed['protocol'] == 'vmess' and parsed['network'] == 'ws':
        return decorate_inbound_config(parsed, instance)

    return get_inbound_config(inbound_id, default_inbounds_for_instance(instance), xui_instance_id=instance['id'])


def get_inbound_config(inbound_id, inbounds=None, xui_instance_id=None):
    """根据入站 ID 获取展示配置，优先使用实时列表。"""
    instance = get_xui_instance(xui_instance_id)
    catalog = default_inbounds_for_instance(instance) if inbounds is None else inbounds
    try:
        inbound_id = int(inbound_id)
    except (TypeError, ValueError):
        inbound_id = 14

    node_key = make_node_key(instance['id'], inbound_id)
    if node_key in catalog:
        return catalog[node_key]

    for config in catalog.values():
        if parse_int(config.get('id')) == inbound_id and parse_int(config.get('xui_instance_id'), instance['id']) == instance['id']:
            return config

    fallback = DEFAULT_INBOUNDS.get(inbound_id, {'name': f'节点{inbound_id}', 'ws_path': '', 'host': ''})
    return decorate_inbound_config({'id': inbound_id, **fallback}, instance)


def parse_node_selection(raw_value, default=14, inbounds=None):
    """解析前台节点选择值，返回 3x-ui 面板 ID 与入站 ID。"""
    catalog = default_inbounds_for_instance() if inbounds is None else inbounds
    if not catalog:
        default_instance = get_default_xui_instance()
        return default_instance['id'], default

    text = str(raw_value or '').strip()
    if ':' in text and text in catalog:
        config = catalog[text]
        return parse_int(config.get('xui_instance_id'), 1), parse_int(config.get('id'), default)

    if ':' in text:
        left, right = text.split(':', 1)
        try:
            instance_id = int(left)
            inbound_id = int(right)
        except (TypeError, ValueError):
            instance_id, inbound_id = None, None
        key = make_node_key(instance_id, inbound_id)
        if key in catalog:
            return instance_id, inbound_id

    try:
        inbound_id = int(text)
    except (TypeError, ValueError):
        inbound_id = default

    for config in catalog.values():
        if parse_int(config.get('id')) == inbound_id:
            return parse_int(config.get('xui_instance_id'), 1), inbound_id

    first_key = next(iter(catalog.keys()))
    config = catalog[first_key]
    return parse_int(config.get('xui_instance_id'), 1), parse_int(config.get('id'), default)


def parse_inbound_id(raw_value, default=14, inbounds=None):
    """兼容旧调用：只返回入站 ID。"""
    return parse_node_selection(raw_value, default=default, inbounds=inbounds)[1]


def has_available_inbounds(inbounds):
    """检查前台是否有已上架节点。"""
    return bool(inbounds)


def format_inbound_name(inbounds, inbound_id, xui_instance_id=None):
    """根据面板 ID + 入站 ID 展示节点名。"""
    if not inbound_id:
        return '-'
    instance = get_xui_instance(xui_instance_id)
    node_key = make_node_key(instance['id'], inbound_id)
    config = (inbounds or {}).get(node_key)
    if not config and inbounds:
        for item in inbounds.values():
            if parse_int(item.get('id')) == parse_int(inbound_id) and parse_int(item.get('xui_instance_id'), instance['id']) == instance['id']:
                config = item
                break
    if config:
        return config.get('display_name') or f"{config.get('xui_instance_name', instance['name'])} · {config.get('name', inbound_id)}"
    return f"ID: {inbound_id} · {instance['name']}"


def is_ldc_configured():
    """检查 LDC 配置"""
    return bool(LDC_CONFIG['pid'] and LDC_CONFIG['key'])


def parse_bool(value, default=False):
    """解析布尔值"""
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ('1', 'true', 'yes', 'on', 'y'):
        return True
    if text in ('0', 'false', 'no', 'off', 'n'):
        return False
    return default


def parse_int(value, default=0):
    """解析整数"""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def parse_decimal(value, default='1'):
    """解析小数字符串"""
    try:
        return Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError, AttributeError):
        return Decimal(str(default))


def load_app_settings(conn=None):
    """读取应用配置"""
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True

    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM app_settings")
    settings = dict(APP_SETTINGS_DEFAULTS)
    settings.update({row['key']: row['value'] for row in cursor.fetchall()})

    if close_conn:
        conn.close()

    return settings


def save_app_settings(settings):
    """保存应用配置"""
    conn = get_db()
    cursor = conn.cursor()
    for key, value in settings.items():
        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
        ''', (key, str(value)))
    conn.commit()
    conn.close()


def get_xui_runtime_config(conn=None):
    """读取 3x-ui 运行时配置。"""
    settings = load_app_settings(conn)
    default_instance = get_default_xui_instance(conn)
    host = (default_instance.get('host') or settings.get('xui_host') or XUI_CONFIG['host']).strip().rstrip('/')
    username = (default_instance.get('username') or settings.get('xui_username') or '').strip()
    password = default_instance.get('password') or settings.get('xui_password') or ''
    expire_days = max(1, parse_int(settings.get('xui_expire_days'), XUI_CONFIG['expire_days']))
    traffic_limit = max(1, parse_int(settings.get('xui_traffic_limit'), XUI_CONFIG['traffic_limit']))

    return {
        'id': default_instance.get('id', 1),
        'name': default_instance.get('name', '默认 3x-ui'),
        'host': host or 'http://127.0.0.1:2053',
        'username': username,
        'password': password,
        'expire_days': expire_days,
        'traffic_limit': traffic_limit,
        'configured': bool(host and username and password),
    }


def get_ldc_usage(conn=None, exclude_order_no=None, include_pending=False):
    """统计 LDC 流量占用；创建订单时可包含待支付订单做预占。"""
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True
        expire_pending_ldc_orders(conn)

    cursor = conn.cursor()
    status_sql = "('pending', 'paid', 'completed')" if include_pending else "('paid', 'completed')"
    if exclude_order_no:
        cursor.execute(f'''
            SELECT COALESCE(SUM(traffic_gb), 0) AS used_gb
            FROM ldc_orders
            WHERE status IN {status_sql}
              AND out_trade_no != ?
        ''', (exclude_order_no,))
    else:
        cursor.execute(f'''
            SELECT COALESCE(SUM(traffic_gb), 0) AS used_gb
            FROM ldc_orders
            WHERE status IN {status_sql}
        ''')
    used_gb = int(cursor.fetchone()['used_gb'] or 0)

    if close_conn:
        conn.close()

    return used_gb


def expire_pending_ldc_orders(conn=None):
    """将超过本地待支付时间的 LDC 订单标记为已过期。"""
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True

    started_in_transaction = conn.in_transaction
    cutoff = local_now() - timedelta(minutes=LDC_PENDING_EXPIRE_MINUTES)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE ldc_orders
            SET status = 'expired',
                error_message = COALESCE(error_message, ?)
            WHERE status = 'pending'
              AND datetime(created_at) <= datetime(?)
        ''', (f'超过 {LDC_PENDING_EXPIRE_MINUTES} 分钟未完成支付，订单已过期', cutoff))
    except sqlite3.OperationalError as exc:
        print(f"LDC 过期订单清理失败: {exc}")
        if conn.in_transaction:
            conn.rollback()
        if close_conn:
            conn.close()
        return 0
    expired_count = cursor.rowcount or 0

    if not close_conn and not started_in_transaction:
        conn.commit()

    if close_conn:
        conn.commit()
        conn.close()

    return expired_count


def get_ldc_runtime_config(conn=None):
    """读取 LDC 运行时配置"""
    if conn is None or not conn.in_transaction:
        expire_pending_ldc_orders(conn)
    settings = load_app_settings(conn)
    enabled = parse_bool(settings.get('ldc_enabled'), False) and is_ldc_configured()
    total_limit_gb = max(0, parse_int(settings.get('ldc_total_limit_gb'), 0))
    ratio = parse_decimal(settings.get('ldc_exchange_ratio'), '1')
    if ratio <= 0:
        ratio = Decimal('1')
    confirmed_used_gb = get_ldc_usage(conn)
    reserved_used_gb = get_ldc_usage(conn, include_pending=True)
    remaining_gb = None if total_limit_gb == 0 else max(total_limit_gb - reserved_used_gb, 0)

    return {
        'enabled': enabled,
        'enabled_setting': parse_bool(settings.get('ldc_enabled'), False),
        'total_limit_gb': total_limit_gb,
        'exchange_ratio': ratio,
        'used_gb': reserved_used_gb,
        'confirmed_used_gb': confirmed_used_gb,
        'remaining_gb': remaining_gb,
        'has_limit': total_limit_gb > 0,
    }


def get_turnstile_config(conn=None):
    """读取 Cloudflare Turnstile 配置。"""
    settings = load_app_settings(conn)
    site_key = (settings.get('turnstile_site_key') or '').strip()
    secret_key = (settings.get('turnstile_secret_key') or '').strip()
    enabled_setting = parse_bool(settings.get('turnstile_enabled'), False)
    return {
        'enabled_setting': enabled_setting,
        'site_key': site_key,
        'secret_key': secret_key,
        'site_key_set': bool(site_key),
        'secret_key_set': bool(secret_key),
        'enabled': enabled_setting and bool(site_key and secret_key),
    }


def verify_turnstile_token(token, remote_ip=None, conn=None):
    """服务端校验 Cloudflare Turnstile token。"""
    config = get_turnstile_config(conn)
    if not config['enabled_setting']:
        return True, ''
    if not config['enabled']:
        return False, 'Turnstile 参数未完整配置'
    if not token:
        return False, '请先完成人机验证'

    try:
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': config['secret_key'],
                'response': token,
                'remoteip': remote_ip or '',
            },
            timeout=8
        )
        result = resp.json()
    except Exception as exc:
        print(f"Turnstile 校验失败: {exc}")
        return False, '人机验证服务暂时不可用'

    if result.get('success') is True:
        return True, ''

    error_codes = ', '.join(result.get('error-codes') or [])
    return False, f"人机验证失败{f'：{error_codes}' if error_codes else ''}"


def require_turnstile_from_request(conn=None):
    """校验当前请求携带的 Turnstile token。"""
    token = (
        request.form.get('cf-turnstile-response') or
        request.form.get('turnstile_token') or
        request.headers.get('CF-Turnstile-Response') or
        request.headers.get('X-Turnstile-Token') or
        ''
    ).strip()
    remote_ip = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr
    return verify_turnstile_token(token, remote_ip=remote_ip, conn=conn)


def get_public_base_url():
    """获取对外访问基址"""
    return PUBLIC_BASE_URL


def build_subscription_url(user_uuid):
    """构造订阅链接"""
    return f"https://{SUB_CONFIG['sub_domain']}/sub/{user_uuid}"


def build_result_data(user_uuid, email, traffic_limit, expire_days, inbound_id, order_no=None, inbounds=None, xui_instance_id=None):
    """统一组装前端展示结果"""
    inbound_config = get_inbound_config(inbound_id, inbounds, xui_instance_id=xui_instance_id)
    data = {
        'uuid': user_uuid,
        'email': email,
        'traffic_limit': f"{traffic_limit} GB",
        'expire_days': expire_days,
        'inbound_name': inbound_config.get('display_name') or inbound_config.get('name', f'节点{inbound_id}'),
        'sub_url': build_subscription_url(user_uuid),
    }
    if order_no:
        data['order_no'] = order_no
    return data


def build_result_from_order(order, inbounds=None):
    """从 LDC 订单记录构造结果"""
    if not order or not order['user_uuid']:
        return None
    return build_result_data(
        order['user_uuid'],
        order['user_email'],
        order['traffic_gb'],
        order['expire_days'],
        order['inbound_id'],
        order_no=order['out_trade_no'],
        inbounds=inbounds,
        xui_instance_id=row_get(order, 'xui_instance_id', 1)
    )


def create_xui_subscription(cursor, inbound_id, traffic_limit, expire_days, redeem_code=None, xui_instance_id=None):
    """创建 3x-ui 客户端并写入本地用户表"""
    instance = get_xui_instance(xui_instance_id)
    client = XUIClient(instance=instance)
    if not client.login():
        raise RuntimeError('服务暂时不可用，请稍后重试')

    user_uuid = generate_uuid()
    email = f"user_{user_uuid[:8]}@redeem.local"

    result = client.add_client(
        inbound_id,
        user_uuid,
        email,
        traffic_limit,
        expire_days
    )
    if not result or not result.get('success'):
        raise RuntimeError('创建节点失败，请联系管理员')

    cursor.execute('''
        INSERT INTO users (uuid, email, inbound_id, xui_instance_id, traffic_limit, expire_at, redeem_code)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_uuid,
        email,
        inbound_id,
        instance['id'],
        traffic_limit,
        local_now() + timedelta(days=expire_days),
        redeem_code
    ))
    return user_uuid, email


def build_ldc_sign(params):
    """按易支付规则生成签名"""
    filtered = {}
    for key, value in params.items():
        if key in ('sign', 'sign_type'):
            continue
        if value is None or value == '':
            continue
        filtered[key] = str(value)

    payload = '&'.join(f'{key}={filtered[key]}' for key in sorted(filtered))
    return hashlib.md5(f"{payload}{LDC_CONFIG['key']}".encode('utf-8')).hexdigest()


def verify_ldc_sign(params):
    """校验 LDC 回调签名"""
    sign = (params.get('sign') or '').strip().lower()
    if not sign:
        return False
    return build_ldc_sign(params) == sign


def normalize_ldc_redirect(location):
    """补全 LDC 返回的跳转地址"""
    if not location:
        return None
    if location.startswith('http://') or location.startswith('https://'):
        return location
    gateway_root = LDC_CONFIG['gateway'].rsplit('/epay', 1)[0]
    if location.startswith('/'):
        return f"{gateway_root}{location}"
    return f"{gateway_root}/{location}"


def get_ldc_gateway_root():
    """获取 LDC 根地址，用于非易支付兼容接口。"""
    return LDC_CONFIG['gateway'].rsplit('/epay', 1)[0].rstrip('/')


def parse_ldc_api_success(result):
    """兼容 LDC JSON 接口的成功字段。"""
    if not isinstance(result, dict):
        return False
    if result.get('success') is True:
        return True
    code = result.get('code')
    if code is not None:
        return str(code) in ('1', '200')
    status = result.get('status')
    return str(status).lower() in ('1', 'success', 'ok', 'true')


def parse_ldc_order_query_success(result):
    """判断订单查询接口本身是否查询成功。"""
    if not isinstance(result, dict):
        return False
    code = result.get('code')
    if code is not None:
        return str(code) == '1'
    return bool(result.get('out_trade_no') or result.get('trade_no'))


def extract_ldc_api_message(result, fallback=''):
    """提取 LDC 接口返回信息。"""
    if isinstance(result, dict):
        for key in ('msg', 'message', 'error_msg', 'error', 'detail'):
            value = result.get(key)
            if value:
                return str(value)
    return fallback


def mask_ldc_payload(payload):
    """写审计日志前隐藏敏感字段。"""
    if not isinstance(payload, dict):
        return payload
    masked = {}
    for key, value in payload.items():
        if key.lower() in ('key', 'client_secret', 'authorization', 'password', 'secret'):
            masked[key] = '***'
        else:
            masked[key] = value
    return masked


def record_ldc_api_action(action, request_payload=None, response_payload=None,
                          success=False, message='', out_trade_no=None, trade_no=None):
    """记录后台手动调用 LDC 接口的审计日志。"""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ldc_api_actions (
                action, out_trade_no, trade_no, request_payload, response_payload,
                success, message, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action,
            out_trade_no,
            trade_no,
            json.dumps(mask_ldc_payload(request_payload or {}), ensure_ascii=False),
            json.dumps(response_payload, ensure_ascii=False) if response_payload is not None else None,
            1 if success else 0,
            message,
            local_now()
        ))
        conn.commit()
    except Exception as exc:
        print(f"LDC 接口日志写入失败: {exc}")
        if conn and conn.in_transaction:
            conn.rollback()
    finally:
        if conn:
            conn.close()


def call_ldc_epay_api(params, method='GET'):
    """调用 LDC 易支付兼容 api.php 接口。"""
    if not is_ldc_configured():
        return None

    payload = {
        'pid': LDC_CONFIG['pid'],
        'key': LDC_CONFIG['key'],
    }
    payload.update(params or {})
    try:
        if method.upper() == 'POST':
            resp = requests.post(
                f"{LDC_CONFIG['gateway']}/api.php",
                data=payload,
                timeout=15
            )
        else:
            resp = requests.get(
                f"{LDC_CONFIG['gateway']}/api.php",
                params=payload,
                timeout=10
            )
        try:
            return resp.json()
        except Exception:
            if resp.status_code == 404:
                return None
            return {
                'code': resp.status_code,
                'msg': resp.text[:300],
            }
    except Exception as exc:
        print(f"LDC 易支付接口调用失败: {exc}")
        return None


def call_ldc_authorized_api(path, method='GET', json_payload=None):
    """调用 LDC Basic Auth 接口。"""
    if not is_ldc_configured():
        return None

    token = base64.b64encode(
        f"{LDC_CONFIG['pid']}:{LDC_CONFIG['key']}".encode('utf-8')
    ).decode('ascii')
    url = f"{get_ldc_gateway_root()}{path}"
    headers = {
        'Authorization': f'Basic {token}',
        'Accept': 'application/json',
    }
    try:
        if method.upper() == 'POST':
            resp = requests.post(url, json=json_payload or {}, headers=headers, timeout=15)
        else:
            resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return None
        try:
            return resp.json()
        except Exception:
            return {
                'success': False,
                'code': resp.status_code,
                'message': resp.text[:300],
            }
    except Exception as exc:
        print(f"LDC 授权接口调用失败: {exc}")
        return None


def call_ldc_public_api(path):
    """调用 LDC 公开 JSON 接口。"""
    url = f"{get_ldc_gateway_root()}{path}"
    try:
        resp = requests.get(url, headers={'Accept': 'application/json'}, timeout=10)
        if resp.status_code == 404:
            return None
        try:
            return resp.json()
        except Exception:
            return {
                'success': False,
                'code': resp.status_code,
                'message': resp.text[:300],
            }
    except Exception as exc:
        print(f"LDC 公开接口调用失败: {exc}")
        return None


def query_ldc_order(out_trade_no):
    """调用 LDC 订单查询接口"""
    return call_ldc_epay_api({
        'act': 'order',
        'out_trade_no': out_trade_no,
    })


def refund_ldc_order(trade_no, money, out_trade_no=None):
    """调用 LDC 全额退款接口。"""
    payload = {
        'trade_no': trade_no,
        'money': money,
    }
    if out_trade_no:
        payload['out_trade_no'] = out_trade_no
    return call_ldc_epay_api(payload, method='POST')


def distribute_ldc_credit(user_id, username, amount, out_trade_no=None, remark=None):
    """调用 LDC 商户积分分发接口。"""
    payload = {
        'user_id': int(user_id),
        'username': username,
        'amount': amount,
    }
    if out_trade_no:
        payload['out_trade_no'] = out_trade_no
    if remark:
        payload['remark'] = remark
    return call_ldc_authorized_api('/lpay/distribute', method='POST', json_payload=payload)


def finalize_ldc_order(out_trade_no, trade_no=None, notify_payload=None, inbounds=None):
    """将已支付的 LDC 订单落地为订阅账号"""
    conn = get_db()
    cursor = conn.cursor()
    payload_text = json.dumps(notify_payload, ensure_ascii=False) if notify_payload else None
    paid_at = local_now()

    try:
        cursor.execute('BEGIN IMMEDIATE')
        expire_pending_ldc_orders(conn)
        cursor.execute("SELECT * FROM ldc_orders WHERE out_trade_no = ?", (out_trade_no,))
        order = cursor.fetchone()

        if not order:
            conn.rollback()
            return False, '订单不存在', None

        if order['status'] == 'completed' and order['user_uuid']:
            data = build_result_from_order(order, inbounds=inbounds)
            conn.commit()
            return True, '', data

        if order['status'] == 'expired':
            conn.commit()
            return False, '订单已过期，请重新创建订单', None

        ldc_runtime = get_ldc_runtime_config(conn)
        if ldc_runtime['has_limit']:
            used_gb = get_ldc_usage(conn, exclude_order_no=out_trade_no)
            if used_gb + int(order['traffic_gb']) > ldc_runtime['total_limit_gb']:
                cursor.execute('''
                    UPDATE ldc_orders
                    SET status = 'failed',
                        error_message = ?
                    WHERE out_trade_no = ?
                ''', ('LDC 兑换总流量已达上限', out_trade_no))
                conn.commit()
                return False, 'LDC 兑换总流量已达上限', None

        cursor.execute('''
            UPDATE ldc_orders
            SET status = 'paid',
                trade_no = COALESCE(?, trade_no),
                paid_at = COALESCE(paid_at, ?),
                notify_payload = COALESCE(?, notify_payload),
                error_message = NULL
            WHERE out_trade_no = ?
        ''', (trade_no, paid_at, payload_text, out_trade_no))

        user_uuid, email = create_xui_subscription(
            cursor,
            order['inbound_id'],
            order['traffic_gb'],
            order['expire_days'],
            xui_instance_id=row_get(order, 'xui_instance_id', 1)
        )

        cursor.execute('''
            UPDATE ldc_orders
            SET status = 'completed',
                trade_no = COALESCE(?, trade_no),
                user_uuid = ?,
                user_email = ?,
                paid_at = COALESCE(paid_at, ?),
                completed_at = ?,
                notify_payload = COALESCE(?, notify_payload),
                error_message = NULL
            WHERE out_trade_no = ?
        ''', (
            trade_no,
            user_uuid,
            email,
            paid_at,
            local_now(),
            payload_text,
            out_trade_no
        ))

        conn.commit()
        return True, '', build_result_data(
            user_uuid,
            email,
            order['traffic_gb'],
            order['expire_days'],
            order['inbound_id'],
            order_no=out_trade_no,
            inbounds=inbounds,
            xui_instance_id=row_get(order, 'xui_instance_id', 1)
        )
    except RuntimeError as exc:
        conn.rollback()

        retry_conn = get_db()
        retry_cursor = retry_conn.cursor()
        retry_cursor.execute('''
            UPDATE ldc_orders
            SET status = 'paid',
                trade_no = COALESCE(?, trade_no),
                paid_at = COALESCE(paid_at, ?),
                notify_payload = COALESCE(?, notify_payload),
                error_message = ?
            WHERE out_trade_no = ?
        ''', (trade_no, paid_at, payload_text, str(exc), out_trade_no))
        retry_conn.commit()
        retry_conn.close()

        return False, str(exc), None
    except Exception as exc:
        conn.rollback()
        print(f"LDC 订单处理失败: {exc}")
        return False, '订单处理失败，请稍后刷新重试', None
    finally:
        conn.close()


# ==================== 3x-ui API 封装 ====================

class XUIClient:
    """3x-ui API 客户端"""

    def __init__(self, instance=None):
        self.instance = normalize_xui_instance(instance) if instance else None
        self.session = requests.Session()
        self.cookie = None

    def reload_config(self):
        """从后台设置刷新 3x-ui 连接参数。"""
        config = self.instance or get_xui_runtime_config()
        self.instance = config
        self.base_url = config['host']
        self.username = config['username']
        self.password = config['password']
        return config

    def login(self):
        """登录获取 session"""
        config = self.reload_config()
        if not config['configured']:
            print("3x-ui 参数未配置")
            return False

        url = f"{self.base_url}/login"
        data = {
            'username': self.username,
            'password': self.password
        }
        try:
            resp = self.session.post(url, data=data, timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                if result.get('success'):
                    self.cookie = self.session.cookies.get('session')
                    return True
        except Exception as exc:
            print(f"登录失败: {exc}")
        return False

    def get_inbound(self, inbound_id):
        """获取指定入站配置"""
        url = f"{self.base_url}/panel/api/inbounds/get/{inbound_id}"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            print(f"获取入站失败: {exc}")
        return None

    def list_inbounds(self):
        """获取全部入站配置"""
        url = f"{self.base_url}/panel/api/inbounds/list"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            print(f"获取入站列表失败: {exc}")
        return None

    def add_client(self, inbound_id, user_uuid, email, traffic_limit_gb, expire_days):
        """添加客户端"""
        inbound = self.get_inbound(inbound_id)
        if not inbound or not inbound.get('success'):
            print("获取入站配置失败")
            return None

        inbound_obj = inbound['obj']
        try:
            settings = json.loads(inbound_obj['settings'])
        except Exception:
            settings = {"clients": []}

        if 'clients' not in settings:
            settings['clients'] = []

        new_client = {
            "id": user_uuid,
            "email": email,
            "enable": True,
            "expiryTime": int((local_now() + timedelta(days=expire_days)).timestamp() * 1000),
            "limitIp": 0,
            "totalGB": traffic_limit_gb * 1024 * 1024 * 1024,
            "tgId": "",
            "subId": "",
            "comment": "",
            "security": "auto",
            "reset": 0
        }
        settings['clients'].append(new_client)

        update_data = {
            "id": inbound_id,
            "up": inbound_obj.get('up', 0),
            "down": inbound_obj.get('down', 0),
            "total": inbound_obj.get('total', 0),
            "remark": inbound_obj.get('remark', ''),
            "enable": inbound_obj.get('enable', True),
            "expiryTime": inbound_obj.get('expiryTime', 0),
            "listen": inbound_obj.get('listen', ''),
            "port": inbound_obj.get('port', 443),
            "protocol": inbound_obj.get('protocol', 'vmess'),
            "settings": json.dumps(settings),
            "streamSettings": inbound_obj.get('streamSettings', '{}'),
            "sniffing": inbound_obj.get('sniffing', '{}'),
            "tag": inbound_obj.get('tag', '')
        }

        url = f"{self.base_url}/panel/api/inbounds/update/{inbound_id}"
        try:
            resp = self.session.post(url, data=update_data, timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            print(f"添加客户端失败: {exc}")
        return None


xui_client = XUIClient()


# ==================== 路由 ====================

@app.route('/')
def index():
    """用户页面"""
    inbounds = get_available_inbounds()
    inbounds_available = has_available_inbounds(inbounds)
    conn = get_db()
    ldc_runtime = get_ldc_runtime_config(conn)
    xui_runtime = get_xui_runtime_config(conn)
    turnstile_config = get_turnstile_config(conn)
    conn.close()

    ldc_default_traffic = min(
        max(xui_runtime['traffic_limit'], LDC_CONFIG['min_traffic']),
        LDC_CONFIG['max_traffic']
    )
    ldc_limit_text = '不限' if ldc_runtime['total_limit_gb'] == 0 else f"{ldc_runtime['total_limit_gb']} GB"
    ldc_used_text = f"{ldc_runtime['used_gb']} GB"
    ldc_remaining_text = '不限' if ldc_runtime['remaining_gb'] is None else f"{ldc_runtime['remaining_gb']} GB"
    return render_template(
        'index.html',
        inbounds=inbounds,
        inbounds_available=inbounds_available,
        ldc_enabled=ldc_runtime['enabled'],
        ldc_enabled_setting=ldc_runtime['enabled_setting'],
        ldc_min_traffic=LDC_CONFIG['min_traffic'],
        ldc_max_traffic=LDC_CONFIG['max_traffic'],
        default_traffic=ldc_default_traffic,
        default_days=xui_runtime['expire_days'],
        ldc_exchange_ratio=str(ldc_runtime['exchange_ratio']),
        ldc_total_limit_text=ldc_limit_text,
        ldc_used_text=ldc_used_text,
        ldc_remaining_text=ldc_remaining_text,
        turnstile_enabled=turnstile_config['enabled'],
        turnstile_site_key=turnstile_config['site_key']
    )


@app.route('/ldc')
def ldc_page():
    """LDC 兑换页直达入口"""
    return redirect(url_for('index', tab='ldc'))


@app.route('/redeem', methods=['POST'])
def redeem():
    """处理兑换码兑换请求"""
    code = request.form.get('code', '').strip().upper()
    ok, msg = require_turnstile_from_request()
    if not ok:
        return jsonify({'success': False, 'msg': msg})

    inbounds = get_available_inbounds()
    if not has_available_inbounds(inbounds):
        return jsonify({'success': False, 'msg': '当前没有上架节点，请联系管理员'})
    xui_instance_id, inbound_id = parse_node_selection(request.form.get('inbound', ''), inbounds=inbounds)

    if not code:
        return jsonify({'success': False, 'msg': '请输入兑换码'})

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute("SELECT * FROM redeem_codes WHERE code = ?", (code,))
        redeem_info = cursor.fetchone()

        if not redeem_info:
            conn.rollback()
            return jsonify({'success': False, 'msg': '兑换码不存在'})

        if redeem_info['used']:
            conn.rollback()
            return jsonify({'success': False, 'msg': '兑换码已被使用'})

        user_uuid, email = create_xui_subscription(
            cursor,
            inbound_id,
            redeem_info['traffic_limit'],
            redeem_info['expire_days'],
            redeem_code=code,
            xui_instance_id=xui_instance_id
        )

        cursor.execute('''
            UPDATE redeem_codes
            SET used = 1, used_by = ?, used_at = ?, inbound_id = ?, xui_instance_id = ?
            WHERE code = ?
        ''', (email, local_now(), inbound_id, xui_instance_id, code))

        conn.commit()
    except RuntimeError as exc:
        conn.rollback()
        return jsonify({'success': False, 'msg': str(exc)})
    except Exception as exc:
        conn.rollback()
        print(f"兑换码兑换失败: {exc}")
        return jsonify({'success': False, 'msg': '兑换失败，请稍后重试'})
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'msg': '兑换成功！',
        'data': build_result_data(
            user_uuid,
            email,
            redeem_info['traffic_limit'],
            redeem_info['expire_days'],
            inbound_id,
            inbounds=inbounds,
            xui_instance_id=xui_instance_id
        )
    })


@app.route('/query', methods=['POST'])
def query_code():
    """查询兑换码或 LDC 订单对应的订阅信息"""
    query_value = request.form.get('code', '').strip().upper()
    ok, msg = require_turnstile_from_request()
    if not ok:
        return jsonify({'success': False, 'msg': msg})

    if not query_value:
        return jsonify({'success': False, 'msg': '请输入兑换码或 LDC 订单号'})

    conn = get_db()
    expire_pending_ldc_orders(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM redeem_codes WHERE code = ?", (query_value,))
    redeem_info = cursor.fetchone()

    if redeem_info:
        if not redeem_info['used']:
            conn.close()
            return jsonify({'success': False, 'msg': '该兑换码尚未使用'})

        cursor.execute("SELECT * FROM users WHERE redeem_code = ? ORDER BY id ASC LIMIT 1", (query_value,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({'success': False, 'msg': '未找到对应的用户信息'})

        inbounds = get_available_inbounds()
        return jsonify({
            'success': True,
            'msg': '查询成功',
            'data': build_result_data(
                user['uuid'],
                user['email'],
                user['traffic_limit'],
                redeem_info['expire_days'],
                user['inbound_id'] or 14,
                inbounds=inbounds,
                xui_instance_id=row_get(user, 'xui_instance_id', row_get(redeem_info, 'xui_instance_id', 1))
            )
        })

    cursor.execute("SELECT * FROM ldc_orders WHERE out_trade_no = ?", (query_value,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        return jsonify({'success': False, 'msg': '兑换码或 LDC 订单号不存在'})

    if order['status'] == 'completed' and order['user_uuid']:
        data = build_result_from_order(order, inbounds=get_available_inbounds())
        conn.close()
        return jsonify({'success': True, 'msg': '查询成功', 'data': data})

    if order['status'] == 'failed':
        error_message = order['error_message'] or 'LDC 订单处理失败'
        conn.close()
        return jsonify({'success': False, 'msg': error_message})

    if order['status'] == 'expired':
        conn.close()
        return jsonify({'success': False, 'msg': 'LDC 订单已过期，请重新创建订单'})

    conn.close()

    remote_order = query_ldc_order(query_value)
    if remote_order and str(remote_order.get('status')) == '1':
        ok, msg, data = finalize_ldc_order(
            query_value,
            trade_no=remote_order.get('trade_no'),
            notify_payload=remote_order,
            inbounds=get_available_inbounds()
        )
        if ok and data:
            return jsonify({'success': True, 'msg': '查询成功', 'data': data})
        return jsonify({'success': False, 'msg': msg or '订单已支付，但订阅生成失败'})

    return jsonify({'success': False, 'msg': 'LDC 订单尚未完成，请支付完成后稍后查询'})


@app.route('/ldc/create', methods=['POST'])
def create_ldc_order():
    """创建 LDC 支付订单"""
    ok, msg = require_turnstile_from_request()
    if not ok:
        return jsonify({'success': False, 'msg': msg})

    inbounds = get_available_inbounds()
    if not has_available_inbounds(inbounds):
        return jsonify({'success': False, 'msg': '当前没有上架节点，请联系管理员'})
    xui_instance_id, inbound_id = parse_node_selection(request.form.get('inbound', ''), inbounds=inbounds)

    try:
        traffic_gb = int(request.form.get('traffic', '0'))
    except (TypeError, ValueError):
        traffic_gb = 0

    if traffic_gb < LDC_CONFIG['min_traffic'] or traffic_gb > LDC_CONFIG['max_traffic']:
        return jsonify({
            'success': False,
            'msg': f"兑换流量需在 {LDC_CONFIG['min_traffic']} - {LDC_CONFIG['max_traffic']} GB 之间"
        })

    conn = get_db()
    cursor = conn.cursor()
    out_trade_no = None
    try:
        expire_pending_ldc_orders(conn)
        settings = load_app_settings(conn)
        if not parse_bool(settings.get('ldc_enabled'), False) or not is_ldc_configured():
            return jsonify({'success': False, 'msg': 'LDC 功能未开启'})

        total_limit_gb = max(0, parse_int(settings.get('ldc_total_limit_gb'), 0))
        xui_runtime = get_xui_runtime_config(conn)
        used_gb = get_ldc_usage(conn, include_pending=True)
        if total_limit_gb > 0 and used_gb + traffic_gb > total_limit_gb:
            remaining_gb = max(total_limit_gb - used_gb, 0)
            return jsonify({
                'success': False,
                'msg': f'当前剩余可兑换流量仅 {remaining_gb} GB，已包含待支付订单占用'
            })

        ratio = parse_decimal(settings.get('ldc_exchange_ratio'), '1')
        if ratio <= 0:
            return jsonify({'success': False, 'msg': '兑换比例必须大于 0'})

        out_trade_no = generate_order_no()
        amount = (Decimal(traffic_gb) * ratio).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        order_name = f"节点兑换 {traffic_gb}GB"
        notify_url = f"{get_public_base_url()}{url_for('ldc_notify')}"
        return_url = f"{get_public_base_url()}{url_for('ldc_return')}?order_no={out_trade_no}"

        cursor.execute('''
            INSERT INTO ldc_orders (out_trade_no, order_name, inbound_id, xui_instance_id, traffic_gb, expire_days, amount, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        ''', (
            out_trade_no,
            order_name,
            inbound_id,
            xui_instance_id,
            traffic_gb,
            xui_runtime['expire_days'],
            format(amount, 'f'),
            local_now()
        ))
        conn.commit()

        payload = {
            'pid': LDC_CONFIG['pid'],
            'type': 'epay',
            'out_trade_no': out_trade_no,
            'name': order_name,
            'money': format(amount, 'f'),
            'notify_url': notify_url,
            'return_url': return_url,
            'sign_type': 'MD5',
        }
        payload['sign'] = build_ldc_sign(payload)

        resp = requests.post(
            f"{LDC_CONFIG['gateway']}/pay/submit.php",
            data=payload,
            allow_redirects=False,
            timeout=15
        )
    except Exception as exc:
        if out_trade_no:
            try:
                cursor.execute(
                    "UPDATE ldc_orders SET status = 'failed', error_message = ? WHERE out_trade_no = ?",
                    (str(exc), out_trade_no)
                )
                conn.commit()
            except Exception:
                conn.rollback()
        print(f"LDC 创建订单失败: {exc}")
        return jsonify({'success': False, 'msg': '积分订单创建失败，请稍后重试'})
    finally:
        conn.close()

    pay_url = normalize_ldc_redirect(resp.headers.get('Location'))
    if not pay_url and resp.history:
        pay_url = normalize_ldc_redirect(resp.url)

    if pay_url:
        return jsonify({'success': True, 'pay_url': pay_url, 'order_no': out_trade_no})

    error_msg = '创建积分订单失败'
    try:
        result = resp.json()
        error_msg = result.get('error_msg') or result.get('msg') or error_msg
    except Exception:
        pass

    fail_conn = get_db()
    fail_cursor = fail_conn.cursor()
    fail_cursor.execute(
        "UPDATE ldc_orders SET status = 'failed', error_message = ? WHERE out_trade_no = ?",
        (error_msg, out_trade_no)
    )
    fail_conn.commit()
    fail_conn.close()

    return jsonify({'success': False, 'msg': error_msg})


@app.route('/ldc/notify')
def ldc_notify():
    """处理 LDC 支付回调"""
    params = request.args.to_dict(flat=True)
    out_trade_no = (params.get('out_trade_no') or '').strip()

    if not is_ldc_configured():
        return 'fail', 500

    if not out_trade_no:
        return 'fail', 400

    if not verify_ldc_sign(params):
        print(f"LDC 回调验签失败: {params}")
        return 'fail', 400

    if params.get('trade_status') != 'TRADE_SUCCESS':
        return 'fail', 400

    ok, _, _ = finalize_ldc_order(
        out_trade_no,
        trade_no=params.get('trade_no'),
        notify_payload=params
    )
    return 'success' if ok else 'fail'


@app.route('/ldc/return')
def ldc_return():
    """LDC 支付完成后的返回页"""
    order_no = request.args.get('order_no', '').strip()
    if not order_no:
        return redirect(url_for('index'))
    return render_template('ldc_return.html', order_no=order_no)


@app.route('/ldc/order/<out_trade_no>')
def ldc_order_status(out_trade_no):
    """查询 LDC 订单状态"""
    conn = get_db()
    expire_pending_ldc_orders(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ldc_orders WHERE out_trade_no = ?", (out_trade_no,))
    order = cursor.fetchone()
    conn.close()

    if not order:
        return jsonify({'success': False, 'status': 'missing', 'msg': '订单不存在'}), 404

    if order['status'] == 'completed' and order['user_uuid']:
        return jsonify({
            'success': True,
            'status': 'completed',
            'data': build_result_from_order(order, inbounds=get_available_inbounds())
        })

    if order['status'] == 'expired':
        return jsonify({
            'success': False,
            'status': 'expired',
            'msg': order['error_message'] or '订单已过期，请重新创建订单'
        })

    remote_order = query_ldc_order(out_trade_no)
    if remote_order and str(remote_order.get('status')) == '1':
        ok, msg, data = finalize_ldc_order(
            out_trade_no,
            trade_no=remote_order.get('trade_no'),
            notify_payload=remote_order,
            inbounds=get_available_inbounds()
        )
        if ok:
            return jsonify({'success': True, 'status': 'completed', 'data': data})
        return jsonify({
            'success': False,
            'status': 'processing',
            'msg': msg or '支付已完成，正在生成订阅'
        })

    if order['status'] == 'failed':
        return jsonify({
            'success': False,
            'status': 'failed',
            'msg': order['error_message'] or '订单处理失败'
        })

    return jsonify({
        'success': False,
        'status': order['status'] or 'pending',
        'msg': '等待积分支付确认'
    })


@app.route('/sub/<user_uuid>')
def subscription(user_uuid):
    """生成订阅内容"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE uuid = ?", (user_uuid,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return "用户不存在", 404

    inbound_id = user['inbound_id'] or 14
    xui_instance_id = row_get(user, 'xui_instance_id', 1)
    inbound_config = get_live_inbound_config(inbound_id, xui_instance_id=xui_instance_id)

    vmess_config = {
        "v": "2",
        "ps": user['email'],
        "add": SUB_CONFIG['domain'],
        "port": str(SUB_CONFIG['port']),
        "id": user['uuid'],
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": inbound_config['host'],
        "path": inbound_config['ws_path'],
        "tls": "tls",
        "sni": "",
        "alpn": "",
        "fp": ""
    }

    vmess_link = "vmess://" + base64.b64encode(
        json.dumps(vmess_config).encode()
    ).decode()
    return vmess_link, 200, {'Content-Type': 'text/plain'}


# ==================== 管理后台 ====================

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_user'):
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login')
def admin_login_page():
    """管理员登录页面"""
    turnstile_config = get_turnstile_config()
    return render_template(
        'admin_login.html',
        turnstile_enabled=turnstile_config['enabled'],
        turnstile_site_key=turnstile_config['site_key']
    )


@app.route('/admin/login', methods=['POST'])
@csrf_required
def admin_login():
    """管理员登录"""
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    ok, msg = require_turnstile_from_request()
    if not ok:
        return jsonify({'success': False, 'msg': msg})

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM admins WHERE username = ?",
        (username,)
    )
    admin = cursor.fetchone()

    if admin and verify_password(admin['password'], password):
        if len(admin['password']) == 64 and all(ch in string.hexdigits for ch in admin['password']):
            cursor.execute(
                "UPDATE admins SET password = ? WHERE id = ?",
                (hash_password(password), admin['id'])
            )
            conn.commit()
        conn.close()
        session.clear()
        session.permanent = True
        session['admin_user'] = admin['username']
        get_csrf_token()
        return jsonify({'success': True})

    conn.close()
    return jsonify({'success': False, 'msg': '用户名或密码错误'})


@app.route('/admin')
@admin_required
def admin_dashboard():
    """管理后台首页"""
    inbounds = get_available_inbounds()
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM redeem_codes")
    total_codes = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as used FROM redeem_codes WHERE used = 1")
    used_codes = cursor.fetchone()['used']

    cursor.execute("SELECT COUNT(*) as total FROM users")
    total_users = cursor.fetchone()['total']

    cursor.execute('''
        SELECT r.code, r.used_by, r.used_at, r.traffic_limit, r.expire_days, r.inbound_id, r.xui_instance_id
        FROM redeem_codes r
        WHERE r.used = 1
        ORDER BY r.used_at DESC
        LIMIT 10
    ''')
    recent_redeems = cursor.fetchall()

    conn.close()

    return render_template(
        'admin_dashboard.html',
        total_codes=total_codes,
        used_codes=used_codes,
        total_users=total_users,
        recent_redeems=recent_redeems,
        inbounds=inbounds,
        format_inbound_name=format_inbound_name
    )


@app.route('/admin/profile')
@admin_required
def admin_profile():
    """个人中心"""
    return redirect(url_for('admin_settings', _anchor='account'))


@app.route('/admin/settings')
@admin_required
def admin_settings():
    """统一设置页面"""
    conn = get_db()
    settings = load_app_settings(conn)
    ldc_runtime = get_ldc_runtime_config(conn)
    xui_runtime = get_xui_runtime_config(conn)
    turnstile_config = get_turnstile_config(conn)
    xui_instances = get_xui_instances(conn, include_disabled=True)
    xui_inbounds = fetch_all_xui_inbounds(include_disabled=True, include_disabled_instances=True) or default_inbounds_for_instance()
    xui_enabled_node_keys = parse_node_key_list(settings.get('xui_enabled_nodes'), default_instance_id=xui_runtime['id'])
    admin_username = session.get('admin_user', '')
    ldc_limit_text = '不限' if ldc_runtime['total_limit_gb'] == 0 else f"{ldc_runtime['total_limit_gb']} GB"
    ldc_remaining_text = '不限' if ldc_runtime['remaining_gb'] is None else f"{ldc_runtime['remaining_gb']} GB"
    conn.close()

    return render_template(
        'admin_settings.html',
        admin_username=admin_username,
        xui_host=xui_runtime['host'],
        xui_username=xui_runtime['username'],
        xui_password_set=bool(xui_runtime['password']),
        xui_expire_days=xui_runtime['expire_days'],
        xui_traffic_limit=xui_runtime['traffic_limit'],
        xui_configured=xui_runtime['configured'],
        xui_instances=xui_instances,
        xui_inbounds=xui_inbounds,
        xui_enabled_node_keys=xui_enabled_node_keys,
        xui_whitelist_enabled=bool(xui_enabled_node_keys),
        ldc_enabled=ldc_runtime['enabled_setting'],
        ldc_effective_enabled=ldc_runtime['enabled'],
        ldc_total_limit_gb=ldc_runtime['total_limit_gb'],
        ldc_total_limit_text=ldc_limit_text,
        ldc_used_gb=ldc_runtime['used_gb'],
        ldc_confirmed_used_gb=ldc_runtime['confirmed_used_gb'],
        ldc_remaining_text=ldc_remaining_text,
        ldc_exchange_ratio=str(ldc_runtime['exchange_ratio']),
        turnstile_enabled=turnstile_config['enabled_setting'],
        turnstile_effective_enabled=turnstile_config['enabled'],
        turnstile_site_key=turnstile_config['site_key'],
        turnstile_secret_key_set=turnstile_config['secret_key_set']
    )


@app.route('/admin/ldc-settings')
@admin_required
def ldc_settings_page():
    """LDC 设置页面"""
    return redirect(url_for('admin_settings', _anchor='ldc'))


@app.route('/admin/ldc-settings', methods=['POST'])
@admin_required
@csrf_required
def update_ldc_settings():
    """更新 LDC 配置"""
    enabled = '1' if request.form.get('ldc_enabled') in ('1', 'on', 'true', 'yes') else '0'

    try:
        total_limit_gb = int(request.form.get('ldc_total_limit_gb', '0'))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'msg': '总流量限制必须是整数'})

    try:
        exchange_ratio = Decimal(str(request.form.get('ldc_exchange_ratio', '1')).strip())
    except (InvalidOperation, TypeError, ValueError, AttributeError):
        return jsonify({'success': False, 'msg': '兑换比例必须是有效数字'})

    if total_limit_gb < 0:
        return jsonify({'success': False, 'msg': '总流量限制不能小于 0'})

    if exchange_ratio <= 0:
        return jsonify({'success': False, 'msg': '兑换比例必须大于 0'})

    save_app_settings({
        'ldc_enabled': enabled,
        'ldc_total_limit_gb': str(total_limit_gb),
        'ldc_exchange_ratio': format(exchange_ratio.normalize(), 'f') if exchange_ratio == exchange_ratio.to_integral() else format(exchange_ratio, 'f')
    })

    return jsonify({'success': True, 'msg': 'LDC 配置已保存'})


@app.route('/admin/turnstile-settings', methods=['POST'])
@admin_required
@csrf_required
def update_turnstile_settings():
    """更新 Cloudflare Turnstile 配置。"""
    enabled = '1' if request.form.get('turnstile_enabled') in ('1', 'on', 'true', 'yes') else '0'
    site_key = (request.form.get('turnstile_site_key') or '').strip()
    secret_key = (request.form.get('turnstile_secret_key') or '').strip()

    if enabled == '1' and not site_key:
        return jsonify({'success': False, 'msg': '开启 Turnstile 时必须填写 Site Key'})

    current = get_turnstile_config()
    if enabled == '1' and not secret_key and not current['secret_key']:
        return jsonify({'success': False, 'msg': '开启 Turnstile 时必须填写 Secret Key'})

    settings = {
        'turnstile_enabled': enabled,
        'turnstile_site_key': site_key,
    }
    if secret_key:
        settings['turnstile_secret_key'] = secret_key

    save_app_settings(settings)
    return jsonify({'success': True, 'msg': 'Turnstile 配置已保存'})


@app.route('/admin/xui-settings', methods=['POST'])
@admin_required
@csrf_required
def update_xui_settings():
    """更新 3x-ui 配置"""
    enabled_node_keys = sorted(parse_node_key_list(request.form.getlist('xui_enabled_nodes')))

    try:
        expire_days = int(request.form.get('xui_expire_days', '30'))
        traffic_limit = int(request.form.get('xui_traffic_limit', '20'))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'msg': '默认流量和有效期必须是整数'})

    if expire_days < 1:
        return jsonify({'success': False, 'msg': '默认有效期必须大于 0'})
    if traffic_limit < 1:
        return jsonify({'success': False, 'msg': '默认流量必须大于 0'})

    conn = get_db()
    cursor = conn.cursor()
    try:
        instances = get_xui_instances(conn, include_disabled=True)
        if not instances:
            raise RuntimeError('没有可编辑的 3x-ui 面板，请刷新页面后重试')

        for instance in instances:
            instance_id = instance['id']
            prefix = f"xui_instance_{instance_id}_"
            host = (request.form.get(prefix + 'host') or '').strip().rstrip('/')
            username = (request.form.get(prefix + 'username') or '').strip()
            password = request.form.get(prefix + 'password') or ''
            name = (request.form.get(prefix + 'name') or '').strip() or f"3x-ui #{instance_id}"
            enabled = 1 if request.form.get(prefix + 'enabled') in ('1', 'on', 'true', 'yes') else 0

            if enabled:
                if not host:
                    return jsonify({'success': False, 'msg': f'请填写{name}的 3x-ui 地址'})
                if not host.startswith(('http://', 'https://')):
                    return jsonify({'success': False, 'msg': f'{name} 的地址必须以 http:// 或 https:// 开头'})
                if not username:
                    return jsonify({'success': False, 'msg': f'请填写{name}的用户名'})
                if not password and not instance['password']:
                    return jsonify({'success': False, 'msg': f'请填写{name}的密码'})

            update_fields = [
                name,
                host or instance['host'],
                username,
                enabled,
                local_now(),
                instance_id,
            ]
            if password:
                cursor.execute('''
                    UPDATE xui_instances
                    SET name = ?, host = ?, username = ?, password = ?, enabled = ?, updated_at = ?
                    WHERE id = ?
                ''', (name, host or instance['host'], username, password, enabled, local_now(), instance_id))
            else:
                cursor.execute('''
                    UPDATE xui_instances
                    SET name = ?, host = ?, username = ?, enabled = ?, updated_at = ?
                    WHERE id = ?
                ''', update_fields)

        new_host = (request.form.get('new_xui_host') or '').strip().rstrip('/')
        new_username = (request.form.get('new_xui_username') or '').strip()
        new_password = request.form.get('new_xui_password') or ''
        new_name = (request.form.get('new_xui_name') or '').strip()
        if new_host or new_username or new_password or new_name:
            if not new_name:
                new_name = f"3x-ui #{len(instances) + 1}"
            if not new_host:
                return jsonify({'success': False, 'msg': '新增面板请填写 3x-ui 地址'})
            if not new_host.startswith(('http://', 'https://')):
                return jsonify({'success': False, 'msg': '新增面板地址必须以 http:// 或 https:// 开头'})
            if not new_username:
                return jsonify({'success': False, 'msg': '新增面板请填写用户名'})
            if not new_password:
                return jsonify({'success': False, 'msg': '新增面板请填写密码'})
            cursor.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order FROM xui_instances")
            next_order = cursor.fetchone()['next_order'] or 1
            cursor.execute('''
                INSERT INTO xui_instances (
                    name, host, username, password, enabled, sort_order, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            ''', (new_name, new_host, new_username, new_password, next_order, local_now(), local_now()))

        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
        ''', ('xui_expire_days', str(expire_days)))
        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
        ''', ('xui_traffic_limit', str(traffic_limit)))
        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
        ''', ('xui_enabled_nodes', ','.join(enabled_node_keys)))

        default_instance = get_default_xui_instance(conn)
        if default_instance['enabled']:
            cursor.execute("SELECT * FROM xui_instances WHERE id = ?", (default_instance['id'],))
        else:
            cursor.execute("SELECT * FROM xui_instances WHERE enabled = 1 ORDER BY sort_order ASC, id ASC LIMIT 1")
        refreshed_default = cursor.fetchone()
        if refreshed_default:
            default_instance = normalize_xui_instance(refreshed_default)
        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES ('xui_host', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        ''', (default_instance['host'],))
        cursor.execute('''
            INSERT INTO app_settings (key, value, updated_at)
            VALUES ('xui_username', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        ''', (default_instance['username'],))
        if default_instance['password']:
            cursor.execute('''
                INSERT INTO app_settings (key, value, updated_at)
                VALUES ('xui_password', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            ''', (default_instance['password'],))

        conn.commit()
    except RuntimeError as exc:
        conn.rollback()
        return jsonify({'success': False, 'msg': str(exc)})
    except Exception as exc:
        conn.rollback()
        print(f"保存 3x-ui 配置失败: {exc}")
        return jsonify({'success': False, 'msg': '保存 3x-ui 配置失败'})
    finally:
        conn.close()

    return jsonify({'success': True, 'msg': '3x-ui 配置已保存'})


@app.route('/admin/account-settings', methods=['POST'])
@admin_required
@csrf_required
def update_admin_account():
    """更新管理员账号信息"""
    current_username = session.get('admin_user')
    if not current_username:
        return jsonify({'success': False, 'msg': '登录已过期，请重新登录'})

    new_username = (request.form.get('admin_new_username') or '').strip()
    current_password = request.form.get('admin_current_password') or ''
    new_password = request.form.get('admin_new_password') or ''
    confirm_password = request.form.get('admin_confirm_password') or ''

    if not new_username:
        return jsonify({'success': False, 'msg': '新用户名不能为空'})

    if len(new_username) > 64:
        return jsonify({'success': False, 'msg': '新用户名不能超过 64 个字符'})

    if not current_password:
        return jsonify({'success': False, 'msg': '请输入当前密码'})

    if new_username == current_username and not new_password:
        return jsonify({'success': False, 'msg': '请至少修改用户名或密码中的一项'})

    if new_password or confirm_password:
        if new_password != confirm_password:
            return jsonify({'success': False, 'msg': '两次输入的新密码不一致'})
        if len(new_password) < 6:
            return jsonify({'success': False, 'msg': '新密码至少需要 6 个字符'})

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT username, password FROM admins WHERE username = ?",
            (current_username,)
        )
        admin = cursor.fetchone()
        if not admin:
            return jsonify({'success': False, 'msg': '当前账号不存在，请重新登录'})

        if not verify_password(admin['password'], current_password):
            return jsonify({'success': False, 'msg': '当前密码不正确'})

        if new_username != current_username:
            cursor.execute(
                "SELECT 1 FROM admins WHERE username = ?",
                (new_username,)
            )
            if cursor.fetchone():
                return jsonify({'success': False, 'msg': '新用户名已被占用'})

        password_hash = admin['password']
        if new_password:
            password_hash = hash_password(new_password)
        elif len(password_hash) == 64 and all(ch in string.hexdigits for ch in password_hash):
            password_hash = hash_password(current_password)

        cursor.execute(
            "UPDATE admins SET username = ?, password = ? WHERE username = ?",
            (new_username, password_hash, current_username)
        )
        conn.commit()
        session['admin_user'] = new_username
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({'success': False, 'msg': '新用户名已被占用'})
    finally:
        conn.close()

    return jsonify({'success': True, 'msg': '账号信息已更新', 'admin_username': new_username})


@app.route('/admin/ldc-orders')
@admin_required
def list_ldc_orders():
    """查看 LDC 兑换记录"""
    inbounds = get_available_inbounds()
    q = (request.args.get('q') or '').strip()
    status = (request.args.get('status') or '').strip().lower()
    page = max(parse_int(request.args.get('page'), 1), 1)
    page_size = 50

    where_clauses = []
    params = []
    valid_statuses = {'pending', 'paid', 'completed', 'failed', 'expired'}

    if q:
        keyword = f"%{q}%"
        where_clauses.append('('
                             'out_trade_no LIKE ? OR '
                             'trade_no LIKE ? OR '
                             'order_name LIKE ? OR '
                             'user_uuid LIKE ? OR '
                             'user_email LIKE ?'
                             ')')
        params.extend([keyword] * 5)

    if status in valid_statuses:
        where_clauses.append('status = ?')
        params.append(status)
    else:
        status = ''

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ''

    conn = get_db()
    expired_count = expire_pending_ldc_orders(conn)
    cursor = conn.cursor()

    cursor.execute(f'''
        SELECT COUNT(*) AS total
        FROM ldc_orders
        {where_sql}
    ''', params)
    total_orders = int(cursor.fetchone()['total'] or 0)
    total_pages = max((total_orders + page_size - 1) // page_size, 1)
    page = min(page, total_pages)
    offset = (page - 1) * page_size

    cursor.execute(f'''
        SELECT *
        FROM ldc_orders
        {where_sql}
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT ? OFFSET ?
    ''', params + [page_size, offset])
    orders = cursor.fetchall()

    cursor.execute('''
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) AS pending_count,
            COALESCE(SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END), 0) AS paid_count,
            COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) AS completed_count,
            COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed_count,
            COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0) AS expired_count,
            COALESCE(SUM(CASE WHEN refund_status = 'success' THEN 1 ELSE 0 END), 0) AS refunded_count,
            COALESCE(SUM(CASE WHEN refund_status = 'success' THEN CAST(amount AS REAL) ELSE 0 END), 0) AS refunded_amount,
            COALESCE(SUM(CASE WHEN status IN ('paid', 'completed') THEN traffic_gb ELSE 0 END), 0) AS total_traffic_gb,
            COALESCE(SUM(CASE WHEN status IN ('paid', 'completed') THEN CAST(amount AS REAL) ELSE 0 END), 0) AS total_amount
        FROM ldc_orders
    ''')
    summary = cursor.fetchone()
    conn.close()

    return render_template(
        'admin_ldc_orders.html',
        orders=orders,
        total_orders=total_orders,
        total_pages=total_pages,
        page=page,
        page_size=page_size,
        q=q,
        status=status,
        summary=summary,
        inbounds=inbounds,
        expired_count=expired_count,
        format_dt=format_dt,
        format_inbound_name=format_inbound_name
    )


@app.route('/admin/ldc-orders/sync', methods=['POST'])
@admin_required
@csrf_required
def sync_ldc_orders():
    """同步 LDC 远端订单状态"""
    if not is_ldc_configured():
        return jsonify({'success': False, 'msg': 'LDC 参数未配置'})

    conn = get_db()
    expired_count = expire_pending_ldc_orders(conn)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT out_trade_no, status
        FROM ldc_orders
        WHERE status IN ('pending', 'paid')
        ORDER BY id DESC
    ''')
    orders = cursor.fetchall()
    conn.close()

    checked = 0
    completed = 0
    failed = 0
    still_pending = 0
    messages = []

    for order in orders:
        out_trade_no = order['out_trade_no']
        checked += 1
        remote_order = query_ldc_order(out_trade_no)
        if not remote_order:
            still_pending += 1
            messages.append(f"{out_trade_no}: 远端查询失败")
            continue

        if str(remote_order.get('status')) == '1':
            ok, msg, _ = finalize_ldc_order(
                out_trade_no,
                trade_no=remote_order.get('trade_no'),
                notify_payload=remote_order
            )
            if ok:
                completed += 1
            else:
                failed += 1
                messages.append(f"{out_trade_no}: {msg or '同步失败'}")
        else:
            still_pending += 1

    msg = f"同步完成：检查 {checked} 笔，补完成 {completed} 笔，仍待支付 {still_pending} 笔，失败 {failed} 笔，过期 {expired_count} 笔"
    if messages:
        msg += "；" + "；".join(messages[:3])

    return jsonify({
        'success': True,
        'msg': msg,
        'checked': checked,
        'completed': completed,
        'pending': still_pending,
        'failed': failed,
        'expired': expired_count
    })


@app.route('/admin/ldc-tools')
@admin_required
def ldc_tools_page():
    """LDC 商户分发工具。"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT *
        FROM ldc_api_actions
        WHERE action = 'distribute'
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 30
    ''')
    api_actions = cursor.fetchall()
    conn.close()

    return render_template(
        'admin_ldc_tools.html',
        api_actions=api_actions,
        format_dt=format_dt
    )


@app.route('/admin/ldc-orders/<out_trade_no>/remote-query', methods=['POST'])
@admin_required
@csrf_required
def admin_remote_query_ldc_order(out_trade_no):
    """后台手动查询 LDC 远端订单。"""
    if not is_ldc_configured():
        return jsonify({'success': False, 'msg': 'LDC 参数未配置'})

    remote_order = query_ldc_order(out_trade_no)
    success = parse_ldc_order_query_success(remote_order)
    message = extract_ldc_api_message(remote_order, '查询成功' if success else '远端查询失败')
    record_ldc_api_action(
        'order_query',
        request_payload={'act': 'order', 'out_trade_no': out_trade_no},
        response_payload=remote_order,
        success=success,
        message=message,
        out_trade_no=out_trade_no,
        trade_no=remote_order.get('trade_no') if isinstance(remote_order, dict) else None
    )
    if not success:
        return jsonify({'success': False, 'msg': message, 'data': remote_order})

    return jsonify({
        'success': True,
        'msg': message,
        'data': remote_order
    })


@app.route('/admin/ldc-orders/<out_trade_no>/refund', methods=['POST'])
@admin_required
@csrf_required
def admin_refund_ldc_order(out_trade_no):
    """后台手动发起 LDC 订单退款。"""
    if not is_ldc_configured():
        return jsonify({'success': False, 'msg': 'LDC 参数未配置'})

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ldc_orders WHERE out_trade_no = ?", (out_trade_no,))
    order = cursor.fetchone()
    conn.close()

    if not order:
        return jsonify({'success': False, 'msg': '订单不存在'})

    if order['status'] != 'completed':
        return jsonify({'success': False, 'msg': '只有已完成订单可以退款'})

    if order['refund_status'] == 'success':
        return jsonify({'success': False, 'msg': '该订单已记录为退款成功'})

    trade_no = (order['trade_no'] or '').strip()
    if not trade_no:
        remote_order = query_ldc_order(out_trade_no)
        if remote_order and remote_order.get('trade_no'):
            trade_no = str(remote_order.get('trade_no')).strip()
        if not trade_no:
            return jsonify({'success': False, 'msg': '缺少 LDC 交易号，无法退款'})

    result = refund_ldc_order(trade_no, order['amount'], out_trade_no=out_trade_no)
    success = parse_ldc_api_success(result)
    message = extract_ldc_api_message(result, '退款成功' if success else '退款失败')
    payload_text = json.dumps(result, ensure_ascii=False) if result is not None else None

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE ldc_orders
        SET trade_no = COALESCE(NULLIF(?, ''), trade_no),
            refund_status = ?,
            refund_at = CASE WHEN ? = 'success' THEN ? ELSE refund_at END,
            refund_payload = ?,
            refund_message = ?
        WHERE out_trade_no = ?
    ''', (
        trade_no,
        'success' if success else 'failed',
        'success' if success else 'failed',
        local_now(),
        payload_text,
        message,
        out_trade_no
    ))
    conn.commit()
    conn.close()

    record_ldc_api_action(
        'refund',
        request_payload={'act': 'refund', 'out_trade_no': out_trade_no, 'trade_no': trade_no, 'money': order['amount']},
        response_payload=result,
        success=success,
        message=message,
        out_trade_no=out_trade_no,
        trade_no=trade_no
    )

    return jsonify({'success': success, 'msg': message})


@app.route('/admin/ldc/distribute', methods=['POST'])
@admin_required
@csrf_required
def admin_distribute_ldc_credit():
    """后台调用 LDC 商户分发接口。"""
    if not is_ldc_configured():
        return jsonify({'success': False, 'msg': 'LDC 参数未配置'})

    user_id_raw = (request.form.get('user_id') or '').strip()
    username = (request.form.get('username') or '').strip()
    amount_raw = (request.form.get('amount') or '').strip()
    out_trade_no = (request.form.get('out_trade_no') or '').strip()
    remark = (request.form.get('remark') or '').strip()

    if not user_id_raw or not username or not amount_raw:
        return jsonify({'success': False, 'msg': '请填写用户 ID、用户名和分发积分'})

    try:
        user_id = int(user_id_raw)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'msg': '用户 ID 必须是整数'})

    amount = parse_decimal(amount_raw, '0')
    if user_id <= 0:
        return jsonify({'success': False, 'msg': '用户 ID 必须大于 0'})
    if amount <= 0:
        return jsonify({'success': False, 'msg': '分发积分必须大于 0'})

    amount = amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    amount_text = format(amount, 'f')
    result = distribute_ldc_credit(
        user_id=user_id,
        username=username,
        amount=amount_text,
        out_trade_no=out_trade_no or None,
        remark=remark or None
    )
    success = parse_ldc_api_success(result)
    message = extract_ldc_api_message(result, '分发成功' if success else '分发失败')

    record_ldc_api_action(
        'distribute',
        request_payload={
            'user_id': user_id,
            'username': username,
            'amount': amount_text,
            'out_trade_no': out_trade_no,
            'remark': remark,
        },
        response_payload=result,
        success=success,
        message=message,
        out_trade_no=out_trade_no or None
    )

    return jsonify({'success': success, 'msg': message, 'data': result})


@app.route('/admin/generate', methods=['POST'])
@admin_required
@csrf_required
def generate_codes():
    """批量生成兑换码"""
    xui_runtime = get_xui_runtime_config()
    try:
        count = int(request.form.get('count', 1))
        traffic_limit = int(request.form.get('traffic', xui_runtime['traffic_limit']))
        expire_days = int(request.form.get('days', xui_runtime['expire_days']))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'msg': '数量、流量和天数必须是整数'})

    if count < 1:
        return jsonify({'success': False, 'msg': '生成数量必须大于 0'})
    if count > 100:
        count = 100

    if traffic_limit < 1:
        return jsonify({'success': False, 'msg': '流量必须大于 0'})

    if expire_days < 1:
        return jsonify({'success': False, 'msg': '天数必须大于 0'})

    conn = get_db()
    cursor = conn.cursor()

    codes = []
    for _ in range(count):
        code = generate_code()
        cursor.execute('''
            INSERT INTO redeem_codes (code, traffic_limit, expire_days)
            VALUES (?, ?, ?)
        ''', (code, traffic_limit, expire_days))
        codes.append(code)

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'codes': codes})


@app.route('/admin/codes')
@admin_required
def list_codes():
    """查看所有兑换码"""
    inbounds = get_available_inbounds()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM redeem_codes
        ORDER BY created_at DESC
    ''')
    codes = cursor.fetchall()
    conn.close()

    return render_template('admin_codes.html', codes=codes, inbounds=inbounds, format_inbound_name=format_inbound_name)


@app.route('/admin/users')
@admin_required
def list_users():
    """查看所有用户"""
    inbounds = get_available_inbounds()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users
        ORDER BY created_at DESC
    ''')
    users = cursor.fetchall()
    conn.close()

    return render_template(
        'admin_users.html',
        users=users,
        inbounds=inbounds,
        domain=SUB_CONFIG['sub_domain'],
        now=local_now().strftime('%Y-%m-%d %H:%M:%S'),
        format_inbound_name=format_inbound_name
    )


@app.route('/admin/logout')
def admin_logout():
    """管理员登出"""
    session.clear()
    return redirect('/admin/login')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
