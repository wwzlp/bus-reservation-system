from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import sqlite3
import bcrypt
import datetime
import random
import string
import os

app = Flask(__name__, static_folder='public')
CORS(app)

# JWT配置
app.config['JWT_SECRET_KEY'] = 'bus-reservation-system-secret-key-2025'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
jwt = JWTManager(app)

# 数据库文件路径
DB_PATH = 'bus_reservation.db'

# JWT错误处理
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token已过期，请重新登录'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Token无效，请重新登录'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': '缺少认证Token，请先登录'}), 401

def init_database():
    """初始化数据库"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            real_name TEXT NOT NULL,
            student_id TEXT UNIQUE NOT NULL,
            phone TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            violation_count INTEGER DEFAULT 0,
            cancel_count INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建班车路线表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bus_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            departure_location TEXT NOT NULL,
            arrival_location TEXT NOT NULL,
            departure_time TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            days_of_week TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建预约记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            route_id INTEGER NOT NULL,
            reservation_date DATE NOT NULL,
            trip_type TEXT NOT NULL,
            seat_count INTEGER DEFAULT 1,
            status TEXT DEFAULT 'active',
            boarding_code TEXT UNIQUE,
            is_confirmed INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (route_id) REFERENCES bus_routes (id)
        )
    ''')
    
    # 创建违约记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reservation_id INTEGER NOT NULL,
            violation_type TEXT NOT NULL,
            violation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (reservation_id) REFERENCES reservations (id)
        )
    ''')
    
    # 创建申诉记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appeals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            admin_response TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            processed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # 插入默认管理员
    admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, real_name, student_id, is_admin) 
        VALUES (?, ?, ?, ?, ?)
    ''', ('admin', admin_password.decode('utf-8'), '系统管理员', 'ADMIN001', 1))
    
    # # 插入默认班车路线
    # cursor.execute('''
    #     INSERT OR IGNORE INTO bus_routes (name, departure_location, arrival_location, departure_time, capacity, days_of_week) 
    #     VALUES (?, ?, ?, ?, ?, ?)
    # ''', ('班车A', '紫金港校区', '长兴试验基地', '07:50', 16, '1,3,5'))
    
    # cursor.execute('''
    #     INSERT OR IGNORE INTO bus_routes (name, departure_location, arrival_location, departure_time, capacity, days_of_week) 
    #     VALUES (?, ?, ?, ?, ?, ?)
    # ''', ('班车B', '紫金港校区', '余杭试验基地', '07:50', 14, '2,4'))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_boarding_code():
    """生成乘车码"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

# 静态文件服务
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/admin')
def admin():
    return send_from_directory('public', 'admin.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('public', filename)

# 用户注册
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    real_name = data.get('real_name')
    student_id = data.get('student_id')
    phone = data.get('phone', '')
    email = data.get('email', '')
    
    if not all([username, password, real_name, student_id]):
        return jsonify({'error': '请填写所有必填字段'}), 400
    
    # 密码加密
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, real_name, student_id, phone, email) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, hashed_password.decode('utf-8'), real_name, student_id, phone, email))
        conn.commit()
        user_id = cursor.lastrowid
        return jsonify({'message': '注册成功', 'user_id': user_id})
    except sqlite3.IntegrityError:
        return jsonify({'error': '用户名或学号已存在'}), 400
    except Exception as e:
        return jsonify({'error': '注册失败'}), 500
    finally:
        conn.close()

# 用户登录
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': '用户名或密码错误'}), 401
    
    if user['is_banned']:
        return jsonify({'error': '账户已被禁用，请联系管理员'}), 403
    
    # 创建JWT token
    additional_claims = {
        'username': user['username'],
        'is_admin': user['is_admin']
    }
    access_token = create_access_token(identity=str(user['id']), additional_claims=additional_claims)
    
    return jsonify({
        'token': access_token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'real_name': user['real_name'],
            'is_admin': user['is_admin']
        }
    })

# 获取班车路线
@app.route('/api/routes', methods=['GET'])
def get_routes():
    today = datetime.datetime.now().weekday() + 1  # Python weekday: 0=Monday, 转换为1=Monday
    if today == 7:  # Sunday
        today = 0
    
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM bus_routes WHERE is_active = 1').fetchall()
    conn.close()
    
    # 过滤今天可用的路线
    available_routes = []
    for route in routes:
        days = [int(d) for d in route['days_of_week'].split(',')]
        if today in days:
            available_routes.append(dict(route))
    
    return jsonify(available_routes)

# 获取特定日期的班车信息
@app.route('/api/routes/<date>', methods=['GET'])
def get_routes_by_date(date):
    try:
        date_obj = datetime.datetime.strptime(date, '%Y-%m-%d')
        day_of_week = date_obj.weekday() + 1
        if day_of_week == 7:
            day_of_week = 0
    except ValueError:
        return jsonify({'error': '日期格式错误'}), 400
    
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM bus_routes WHERE is_active = 1').fetchall()
    
    available_routes = []
    for route in routes:
        days = [int(d) for d in route['days_of_week'].split(',')]
        if day_of_week in days:
            # 获取预约情况
            reserved_result = conn.execute('''
                SELECT SUM(seat_count) as reserved_seats 
                FROM reservations 
                WHERE route_id = ? AND reservation_date = ? AND status = "active"
            ''', (route['id'], date)).fetchone()
            
            reserved_seats = reserved_result['reserved_seats'] or 0
            route_dict = dict(route)
            route_dict['reserved_seats'] = reserved_seats
            route_dict['available_seats'] = route['capacity'] - reserved_seats
            available_routes.append(route_dict)
    
    conn.close()
    return jsonify(available_routes)

# 创建预约
@app.route('/api/reservations', methods=['POST'])
@jwt_required()
def create_reservation():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    route_id = data.get('route_id')
    reservation_date = data.get('reservation_date')
    trip_type = data.get('trip_type')
    seat_count = data.get('seat_count', 1)
    
    conn = get_db_connection()
    
    # 检查用户是否被禁用
    user = conn.execute('SELECT is_banned FROM users WHERE id = ?', (user_id,)).fetchone()
    if user['is_banned']:
        conn.close()
        return jsonify({'error': '账户已被禁用，无法预约'}), 403
    
    # 获取班车路线信息（包含发车时间）
    route = conn.execute('SELECT departure_time, capacity FROM bus_routes WHERE id = ?', (route_id,)).fetchone()
    if not route:
        conn.close()
        return jsonify({'error': '班车路线不存在'}), 404
    
    # 检查预约时间限制（仅可在发车前72小时内预约）
    try:
        reservation_datetime = datetime.datetime.strptime(f"{reservation_date} {route['departure_time']}", "%Y-%m-%d %H:%M")
        now = datetime.datetime.now()
        hours_until_departure = (reservation_datetime - now).total_seconds() / 3600
        
        if hours_until_departure > 72:
            conn.close()
            return jsonify({'error': '仅可在发车前72小时内预约'}), 400
        
        if hours_until_departure < 0:
            conn.close()
            return jsonify({'error': '班车已发车'}), 400
    except ValueError:
        conn.close()
        return jsonify({'error': '日期格式错误'}), 400
    
    # 检查座位余量
    
    reserved_result = conn.execute('''
        SELECT SUM(seat_count) as reserved_seats 
        FROM reservations 
        WHERE route_id = ? AND reservation_date = ? AND status = "active"
    ''', (route_id, reservation_date)).fetchone()
    
    reserved_seats = reserved_result['reserved_seats'] or 0
    available_seats = route['capacity'] - reserved_seats
    
    if seat_count > available_seats:
        conn.close()
        return jsonify({'error': '座位不足'}), 400
    
    # 创建预约
    boarding_code = generate_boarding_code()
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reservations (user_id, route_id, reservation_date, trip_type, seat_count, boarding_code) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, route_id, reservation_date, trip_type, seat_count, boarding_code))
        conn.commit()
        reservation_id = cursor.lastrowid
        
        return jsonify({
            'message': '预约成功',
            'reservation_id': reservation_id,
            'boarding_code': boarding_code
        })
    except Exception as e:
        return jsonify({'error': '预约失败'}), 500
    finally:
        conn.close()

# 获取用户预约记录
@app.route('/api/my-reservations', methods=['GET'])
@jwt_required()
def get_my_reservations():
    user_id = get_jwt_identity()
    
    conn = get_db_connection()
    reservations = conn.execute('''
        SELECT r.*, br.name as route_name, br.departure_location, br.arrival_location, br.departure_time
        FROM reservations r
        JOIN bus_routes br ON r.route_id = br.id
        WHERE r.user_id = ?
        ORDER BY r.reservation_date DESC, r.created_at DESC
    ''', (user_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in reservations])

# 取消预约
@app.route('/api/reservations/<int:reservation_id>/cancel', methods=['PUT'])
@jwt_required()
def cancel_reservation(reservation_id):
    user_id = get_jwt_identity()
    
    conn = get_db_connection()
    reservation = conn.execute('''
        SELECT * FROM reservations WHERE id = ? AND user_id = ?
    ''', (reservation_id, user_id)).fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({'error': '预约记录不存在'}), 404
    
    if reservation['status'] != 'active':
        conn.close()
        return jsonify({'error': '预约已取消或已完成'}), 400
    
    # 检查是否在发车前
    try:
        reservation_datetime = datetime.datetime.strptime(f"{reservation['reservation_date']} 07:30", "%Y-%m-%d %H:%M")
        now = datetime.datetime.now()
        
        if now > reservation_datetime:
            conn.close()
            return jsonify({'error': '发车后无法取消预约'}), 400
    except ValueError:
        conn.close()
        return jsonify({'error': '日期格式错误'}), 400
    
    # 取消预约并增加取消次数
    cursor = conn.cursor()
    cursor.execute('UPDATE reservations SET status = "cancelled" WHERE id = ?', (reservation_id,))
    cursor.execute('UPDATE users SET cancel_count = cancel_count + 1 WHERE id = ?', (user_id,))
    
    # 添加违约记录
    cursor.execute('''
        INSERT INTO violations (user_id, reservation_id, violation_type, description)
        VALUES (?, ?, ?, ?)
    ''', (user_id, reservation_id, 'cancel', '用户主动取消预约'))
    
    # 检查取消次数是否达到6次
    user = conn.execute('SELECT cancel_count FROM users WHERE id = ?', (user_id,)).fetchone()
    
    message = '预约已取消'
    if user['cancel_count'] >= 6:
        cursor.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (user_id,))
        message = '预约已取消，但由于取消次数过多，账户已被禁用'
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': message})

# 确认上车
@app.route('/api/reservations/<int:reservation_id>/confirm', methods=['PUT'])
@jwt_required()
def confirm_boarding(reservation_id):
    user_id = get_jwt_identity()
    
    conn = get_db_connection()
    
    # 获取预约信息和班车时间
    reservation = conn.execute('''
        SELECT r.*, br.departure_time
        FROM reservations r
        JOIN bus_routes br ON r.route_id = br.id
        WHERE r.id = ? AND r.user_id = ? AND r.status = "active"
    ''', (reservation_id, user_id)).fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({'error': '预约记录不存在或已处理'}), 404
    
    # 检查是否在发车前半小时内
    try:
        reservation_datetime = datetime.datetime.strptime(f"{reservation['reservation_date']} {reservation['departure_time']}", '%Y-%m-%d %H:%M')
        now = datetime.datetime.now()
        minutes_until_departure = (reservation_datetime - now).total_seconds() / 60
        
        if minutes_until_departure > 30:
            conn.close()
            return jsonify({'error': '只能在发车前30分钟内确认上车'}), 400
        
        if minutes_until_departure < -30:
            conn.close()
            return jsonify({'error': '发车后30分钟内未确认，已视为违约'}), 400
    except ValueError:
        conn.close()
        return jsonify({'error': '时间格式错误'}), 500
    
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE reservations SET is_confirmed = 1 
        WHERE id = ? AND user_id = ? AND status = "active"
    ''', (reservation_id, user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': '确认上车成功'})

# 提交申诉
@app.route('/api/appeals', methods=['POST'])
@jwt_required()
def submit_appeal():
    user_id = get_jwt_identity()
    data = request.get_json()
    reason = data.get('reason')
    
    if not reason:
        return jsonify({'error': '请填写申诉理由'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO appeals (user_id, reason) VALUES (?, ?)', (user_id, reason))
    conn.commit()
    conn.close()
    
    return jsonify({'message': '申诉已提交，请等待管理员审核'})

# 管理员API

# 获取所有预约记录
@app.route('/api/admin/reservations', methods=['GET'])
@jwt_required()
def admin_get_reservations():
    # 这里应该检查管理员权限，简化处理
    conn = get_db_connection()
    reservations = conn.execute('''
        SELECT r.*, u.real_name, u.student_id, br.name as route_name
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN bus_routes br ON r.route_id = br.id
        ORDER BY r.reservation_date DESC, r.created_at DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in reservations])

# 获取所有申诉
@app.route('/api/admin/appeals', methods=['GET'])
@jwt_required()
def admin_get_appeals():
    conn = get_db_connection()
    appeals = conn.execute('''
        SELECT a.*, u.real_name, u.student_id
        FROM appeals a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in appeals])

# 处理申诉
@app.route('/api/admin/appeals/<int:appeal_id>', methods=['PUT'])
@jwt_required()
def admin_process_appeal(appeal_id):
    data = request.get_json()
    status = data.get('status')
    admin_response = data.get('admin_response')
    
    conn = get_db_connection()
    appeal = conn.execute('SELECT user_id FROM appeals WHERE id = ?', (appeal_id,)).fetchone()
    
    if not appeal:
        conn.close()
        return jsonify({'error': '申诉记录不存在'}), 404
    
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE appeals SET status = ?, admin_response = ?, processed_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (status, admin_response, appeal_id))
    
    # 如果申诉通过，恢复用户权限
    if status == 'approved':
        cursor.execute('''
            UPDATE users SET is_banned = 0, violation_count = 0, cancel_count = 0 
            WHERE id = ?
        ''', (appeal['user_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': '申诉处理完成'})

# 获取所有班车路线（管理员）
@app.route('/api/admin/routes', methods=['GET'])
@jwt_required()
def admin_get_routes():
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM bus_routes ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in routes])

# 更新班车路线
@app.route('/api/admin/routes/<int:route_id>', methods=['PUT'])
@jwt_required()
def admin_update_route(route_id):
    data = request.get_json()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE bus_routes SET 
        name = ?, departure_location = ?, arrival_location = ?, 
        departure_time = ?, capacity = ?, days_of_week = ?, is_active = ? 
        WHERE id = ?
    ''', (
        data.get('name'), data.get('departure_location'), data.get('arrival_location'),
        data.get('departure_time'), data.get('capacity'), data.get('days_of_week'),
        data.get('is_active'), route_id
    ))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': '路线不存在'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': '路线更新成功'})

# 添加新班车路线
@app.route('/api/admin/routes', methods=['POST'])
@jwt_required()
def admin_add_route():
    data = request.get_json()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO bus_routes (name, departure_location, arrival_location, departure_time, capacity, days_of_week) 
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        data.get('name'), data.get('departure_location'), data.get('arrival_location'),
        data.get('departure_time'), data.get('capacity'), data.get('days_of_week')
    ))
    
    route_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'message': '路线添加成功', 'route_id': route_id})

# 批量删除班车路线
@app.route('/api/admin/routes/batch-delete', methods=['POST'])
@jwt_required()
def admin_batch_delete_routes():
    data = request.get_json()
    route_ids = data.get('route_ids', [])
    
    if not route_ids:
        return jsonify({'error': '请选择要删除的路线'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 检查是否有相关的预约记录
    placeholders = ','.join(['?' for _ in route_ids])
    reservations = cursor.execute(f'''
        SELECT COUNT(*) as count FROM reservations 
        WHERE route_id IN ({placeholders}) AND status = 'confirmed'
    ''', route_ids).fetchone()
    
    if reservations['count'] > 0:
        conn.close()
        return jsonify({'error': f'选中的路线中有 {reservations["count"]} 个确认的预约记录，无法删除'}), 400
    
    # 删除路线
    cursor.execute(f'DELETE FROM bus_routes WHERE id IN ({placeholders})', route_ids)
    deleted_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'成功删除 {deleted_count} 条路线'})

# 批量禁用/启用班车路线
@app.route('/api/admin/routes/batch-status', methods=['POST'])
@jwt_required()
def admin_batch_update_route_status():
    data = request.get_json()
    route_ids = data.get('route_ids', [])
    is_active = data.get('is_active', True)
    
    if not route_ids:
        return jsonify({'error': '请选择要操作的路线'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    placeholders = ','.join(['?' for _ in route_ids])
    cursor.execute(f'UPDATE bus_routes SET is_active = ? WHERE id IN ({placeholders})', [is_active] + route_ids)
    updated_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    action = '启用' if is_active else '禁用'
    return jsonify({'message': f'成功{action} {updated_count} 条路线'})

# 获取所有用户（管理员）
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def admin_get_users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, real_name, student_id, email, phone, 
               is_admin, is_banned, violation_count, cancel_count, created_at
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in users])

# 批量删除用户
@app.route('/api/admin/users/batch-delete', methods=['POST'])
@jwt_required()
def admin_batch_delete_users():
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    
    if not user_ids:
        return jsonify({'error': '请选择要删除的用户'}), 400
    
    # 检查是否包含管理员账户
    conn = get_db_connection()
    admin_users = conn.execute('''
        SELECT id FROM users WHERE id IN ({}) AND is_admin = 1
    '''.format(','.join('?' * len(user_ids))), user_ids).fetchall()
    
    if admin_users:
        conn.close()
        return jsonify({'error': '不能删除管理员账户'}), 400
    
    try:
        cursor = conn.cursor()
        
        # 删除用户相关的预约记录
        cursor.execute('''
            DELETE FROM reservations WHERE user_id IN ({})
        '''.format(','.join('?' * len(user_ids))), user_ids)
        
        # 删除用户相关的申诉记录
        cursor.execute('''
            DELETE FROM appeals WHERE user_id IN ({})
        '''.format(','.join('?' * len(user_ids))), user_ids)
        
        # 删除用户
        cursor.execute('''
            DELETE FROM users WHERE id IN ({})
        '''.format(','.join('?' * len(user_ids))), user_ids)
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'成功删除 {deleted_count} 个用户'})
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': '删除失败，请重试'}), 500

# 批量禁用/启用用户
@app.route('/api/admin/users/batch-ban', methods=['POST'])
@jwt_required()
def admin_batch_ban_users():
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    is_banned = data.get('is_banned', True)
    
    if not user_ids:
        return jsonify({'error': '请选择要操作的用户'}), 400
    
    # 检查是否包含管理员账户
    conn = get_db_connection()
    admin_users = conn.execute('''
        SELECT id FROM users WHERE id IN ({}) AND is_admin = 1
    '''.format(','.join('?' * len(user_ids))), user_ids).fetchall()
    
    if admin_users:
        conn.close()
        return jsonify({'error': '不能禁用管理员账户'}), 400
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET is_banned = ? WHERE id IN ({})
        '''.format(','.join('?' * len(user_ids))), [1 if is_banned else 0] + user_ids)
        
        updated_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        action = '禁用' if is_banned else '启用'
        return jsonify({'message': f'成功{action} {updated_count} 个用户'})
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': '操作失败，请重试'}), 500

# 获取违约记录
@app.route('/api/admin/violations', methods=['GET'])
@jwt_required()
def get_violations():
    user_id = get_jwt_identity()
    
    # 检查管理员权限
    conn = get_db_connection()
    admin = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not admin or not admin['is_admin']:
        conn.close()
        return jsonify({'error': '权限不足'}), 403
    
    violations = conn.execute('''
        SELECT v.*, u.username, u.real_name, u.student_id,
               r.reservation_date, r.boarding_code,
               br.name as route_name, br.departure_location, br.arrival_location, br.departure_time
        FROM violations v
        JOIN users u ON v.user_id = u.id
        JOIN reservations r ON v.reservation_id = r.id
        JOIN bus_routes br ON r.route_id = br.id
        ORDER BY v.violation_date DESC
    ''').fetchall()
    
    conn.close()
    
    return jsonify([dict(row) for row in violations])

# 检查并处理未确认上车的违约
@app.route('/api/admin/check-violations', methods=['POST'])
@jwt_required()
def check_violations():
    user_id = get_jwt_identity()
    
    # 检查管理员权限
    conn = get_db_connection()
    admin = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not admin or not admin['is_admin']:
        conn.close()
        return jsonify({'error': '权限不足'}), 403
    
    # 查找发车后30分钟仍未确认的预约
    now = datetime.datetime.now()
    cursor = conn.cursor()
    
    unconfirmed_reservations = conn.execute('''
        SELECT r.*, br.departure_time
        FROM reservations r
        JOIN bus_routes br ON r.route_id = br.id
        WHERE r.status = "active" AND r.is_confirmed = 0
    ''').fetchall()
    
    violation_count = 0
    
    for reservation in unconfirmed_reservations:
        try:
            reservation_datetime = datetime.datetime.strptime(f"{reservation['reservation_date']} {reservation['departure_time']}", '%Y-%m-%d %H:%M')
            minutes_since_departure = (now - reservation_datetime).total_seconds() / 60
            
            if minutes_since_departure > 30:
                # 检查是否已经记录过违约
                existing_violation = conn.execute('''
                    SELECT id FROM violations 
                    WHERE reservation_id = ? AND violation_type = "no_confirm"
                ''', (reservation['id'],)).fetchone()
                
                if not existing_violation:
                    # 添加违约记录
                    cursor.execute('''
                        INSERT INTO violations (user_id, reservation_id, violation_type, description)
                        VALUES (?, ?, ?, ?)
                    ''', (reservation['user_id'], reservation['id'], 'no_confirm', '发车后30分钟内未确认上车'))
                    
                    # 增加用户违约次数
                    cursor.execute('UPDATE users SET violation_count = violation_count + 1 WHERE id = ?', (reservation['user_id'],))
                    
                    # 检查违约次数是否达到3次
                    user = conn.execute('SELECT violation_count FROM users WHERE id = ?', (reservation['user_id'],)).fetchone()
                    if user['violation_count'] >= 3:
                        cursor.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (reservation['user_id'],))
                    
                    # 将预约状态改为已完成
                    cursor.execute('UPDATE reservations SET status = "completed" WHERE id = ?', (reservation['id'],))
                    
                    violation_count += 1
        except ValueError:
            continue
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'已处理 {violation_count} 条违约记录'})

if __name__ == '__main__':
    # 初始化数据库
    init_database()
    
    # 启动应用
    print("班车预约系统启动中...")
    print("用户端: http://localhost:8000")
    print("管理后台: http://localhost:8000/admin")
    print("默认管理员账户: admin / admin123")
    
    app.run(debug=True, host='0.0.0.0', port=8000)