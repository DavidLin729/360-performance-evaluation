from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import csv
import io
import os
import pandas as pd
import numpy as np
from sqlalchemy import func
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///performance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 用戶角色模型
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    permissions = db.Column(db.Integer, default=0)  # 使用位運算儲存權限

# 用戶模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True)
    employee_id = db.Column(db.String(20), unique=True)  # 員工編號
    full_name = db.Column(db.String(100))  # 全名
    position = db.Column(db.String(100))  # 職位
    hire_date = db.Column(db.Date)  # 到職日期
    is_active = db.Column(db.Boolean, default=True)  # 是否在職
    is_admin = db.Column(db.Boolean, default=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref='users')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def has_permission(self, permission):
        return self.role and (self.role.permissions & permission) == permission

# 權限常數
class Permission:
    VIEW_STATISTICS = 0x01
    MANAGE_USERS = 0x02
    MANAGE_FEEDBACKS = 0x04
    ADMIN = 0xff  # 所有權限

# 部門模型
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    users = db.relationship('User', backref='department', lazy=True)

# 績效評估表模型
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    target_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # 工作能力評估 (1-5分)
    work_quality = db.Column(db.Integer)
    work_efficiency = db.Column(db.Integer)
    work_reliability = db.Column(db.Integer)
    
    # 領導力評估 (1-5分)
    leadership = db.Column(db.Integer)
    decision_making = db.Column(db.Integer)
    team_management = db.Column(db.Integer)
    
    # 團隊合作 (1-5分)
    collaboration = db.Column(db.Integer)
    interpersonal_skills = db.Column(db.Integer)
    conflict_resolution = db.Column(db.Integer)
    
    # 溝通能力 (1-5分)
    communication_skills = db.Column(db.Integer)
    presentation_skills = db.Column(db.Integer)
    listening_skills = db.Column(db.Integer)
    
    # 專業知識 (1-5分)
    technical_knowledge = db.Column(db.Integer)
    industry_knowledge = db.Column(db.Integer)
    problem_solving = db.Column(db.Integer)
    
    # 工作態度 (1-5分)
    work_attitude = db.Column(db.Integer)
    initiative = db.Column(db.Integer)
    responsibility = db.Column(db.Integer)
    
    # 創新思維 (1-5分)
    innovation = db.Column(db.Integer)
    creativity = db.Column(db.Integer)
    adaptability = db.Column(db.Integer)
    
    # 問題解決能力 (1-5分)
    analytical_thinking = db.Column(db.Integer)
    solution_implementation = db.Column(db.Integer)
    risk_management = db.Column(db.Integer)
    
    # 文字回饋
    strengths = db.Column(db.Text)
    improvements = db.Column(db.Text)
    suggestions = db.Column(db.Text)
    
    status = db.Column(db.String(20), default='pending')  # pending 或 completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 管理者驗證裝飾器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('您沒有管理者權限')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    pending_feedbacks = Feedback.query.filter_by(evaluator_id=current_user.id, status='pending').all()
    completed_feedbacks = Feedback.query.filter_by(evaluator_id=current_user.id, status='completed').all()
    return render_template('index.html', 
                         pending_feedbacks=pending_feedbacks, 
                         completed_feedbacks=completed_feedbacks,
                         User=User)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('帳號或密碼錯誤')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/feedback/<int:feedback_id>', methods=['GET', 'POST'])
def feedback(feedback_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    feedback = Feedback.query.get_or_404(feedback_id)
    if request.method == 'POST':
        # 工作能力評估
        feedback.work_quality = int(request.form['work_quality'])
        feedback.work_efficiency = int(request.form['work_efficiency'])
        feedback.work_reliability = int(request.form['work_reliability'])
        
        # 領導力評估
        feedback.leadership = int(request.form['leadership'])
        feedback.decision_making = int(request.form['decision_making'])
        feedback.team_management = int(request.form['team_management'])
        
        # 團隊合作
        feedback.collaboration = int(request.form['collaboration'])
        feedback.interpersonal_skills = int(request.form['interpersonal_skills'])
        feedback.conflict_resolution = int(request.form['conflict_resolution'])
        
        # 溝通能力
        feedback.communication_skills = int(request.form['communication_skills'])
        feedback.presentation_skills = int(request.form['presentation_skills'])
        feedback.listening_skills = int(request.form['listening_skills'])
        
        # 專業知識
        feedback.technical_knowledge = int(request.form['technical_knowledge'])
        feedback.industry_knowledge = int(request.form['industry_knowledge'])
        feedback.problem_solving = int(request.form['problem_solving'])
        
        # 工作態度
        feedback.work_attitude = int(request.form['work_attitude'])
        feedback.initiative = int(request.form['initiative'])
        feedback.responsibility = int(request.form['responsibility'])
        
        # 創新思維
        feedback.innovation = int(request.form['innovation'])
        feedback.creativity = int(request.form['creativity'])
        feedback.adaptability = int(request.form['adaptability'])
        
        # 問題解決能力
        feedback.analytical_thinking = int(request.form['analytical_thinking'])
        feedback.solution_implementation = int(request.form['solution_implementation'])
        feedback.risk_management = int(request.form['risk_management'])
        
        # 文字回饋
        feedback.strengths = request.form['strengths']
        feedback.improvements = request.form['improvements']
        feedback.suggestions = request.form['suggestions']
        
        feedback.status = 'completed'
        db.session.commit()
        flash('評估表單已成功提交')
        return redirect(url_for('index'))
    return render_template('feedback_form.html', feedback=feedback, User=User)

# 管理者路由
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # 獲取系統概況數據
    total_users = User.query.count()
    pending_feedback = Feedback.query.filter_by(status='pending').count()
    completed_feedback = Feedback.query.filter_by(status='completed').count()
    
    # 獲取所有使用者
    users = User.query.all()
    
    # 獲取所有評估任務
    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    
    # 獲取最近活動
    recent_activities = []
    recent_feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).limit(5).all()
    for feedback in recent_feedbacks:
        evaluator = User.query.get(feedback.evaluator_id)
        target = User.query.get(feedback.target_id)
        activity = {
            'description': f'{evaluator.username} 完成了對 {target.username} 的評估',
            'timestamp': feedback.created_at.strftime('%Y-%m-%d %H:%M')
        }
        recent_activities.append(activity)
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         pending_feedback=pending_feedback,
                         completed_feedback=completed_feedback,
                         recent_activities=recent_activities,
                         users=users,
                         feedbacks=feedbacks,
                         User=User)

@app.route('/admin/user/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        if User.query.filter_by(username=username).first():
            flash('使用者名稱已存在')
        else:
            user = User(
                username=username,
                password=generate_password_hash(password),
                is_admin=is_admin
            )
            db.session.add(user)
            db.session.commit()
            flash('使用者建立成功')
            return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_user.html')

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form['username']
        is_admin = 'is_admin' in request.form
        
        if username != user.username and User.query.filter_by(username=username).first():
            flash('使用者名稱已存在')
        else:
            user.username = username
            user.is_admin = is_admin
            if request.form['password']:
                user.password = generate_password_hash(request.form['password'])
            db.session.commit()
            flash('使用者資料更新成功')
            return redirect(url_for('admin_dashboard'))
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/user/<int:user_id>/delete')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'David':
        flash('無法刪除主管理員帳號')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('使用者已刪除')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/create', methods=['GET', 'POST'])
@admin_required
def create_feedback():
    users = User.query.all()
    if request.method == 'POST':
        evaluator_id = request.form['evaluator_id']
        target_id = request.form['target_id']
        
        feedback = Feedback(
            evaluator_id=evaluator_id,
            target_id=target_id,
            status='pending'
        )
        db.session.add(feedback)
        db.session.commit()
        flash('評估任務建立成功')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_feedback.html', users=users)

@app.route('/admin/feedback/upload', methods=['POST'])
@admin_required
def upload_feedback_csv():
    if 'csv_file' not in request.files:
        flash('沒有上傳檔案')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['csv_file']
    if file.filename == '':
        flash('沒有選擇檔案')
        return redirect(url_for('admin_dashboard'))
    
    if not file.filename.endswith('.csv'):
        flash('請上傳CSV檔案')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # 讀取CSV檔案
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_data = csv.DictReader(stream)
        
        # 驗證CSV標題
        required_headers = ['evaluator_username', 'target_username']
        if not all(header in csv_data.fieldnames for header in required_headers):
            flash('CSV檔案格式錯誤，請下載範本查看正確格式')
            return redirect(url_for('admin_dashboard'))
        
        # 處理每一行資料
        success_count = 0
        error_count = 0
        error_messages = []
        
        for row in csv_data:
            evaluator = User.query.filter_by(username=row['evaluator_username']).first()
            target = User.query.filter_by(username=row['target_username']).first()
            
            if not evaluator or not target:
                error_count += 1
                error_messages.append(f"找不到使用者：{row['evaluator_username']} 或 {row['target_username']}")
                continue
            
            # 檢查是否已存在相同的評估任務
            existing_feedback = Feedback.query.filter_by(
                evaluator_id=evaluator.id,
                target_id=target.id
            ).first()
            
            if existing_feedback:
                error_count += 1
                error_messages.append(f"評估任務已存在：{row['evaluator_username']} -> {row['target_username']}")
                continue
            
            # 建立新的評估任務
            feedback = Feedback(
                evaluator_id=evaluator.id,
                target_id=target.id,
                status='pending'
            )
            db.session.add(feedback)
            success_count += 1
        
        db.session.commit()
        
        if success_count > 0:
            flash(f'成功匯入 {success_count} 筆評估任務')
        if error_count > 0:
            flash(f'匯入失敗 {error_count} 筆：' + '; '.join(error_messages))
        
    except Exception as e:
        flash(f'檔案處理錯誤：{str(e)}')
        db.session.rollback()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/template')
@admin_required
def download_csv_template():
    # 建立CSV範本
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['evaluator_username', 'target_username'])
    writer.writerow(['user1', 'user2'])
    writer.writerow(['user2', 'user3'])
    
    # 準備下載
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='feedback_template.csv'
    )

@app.route('/admin/users/template')
@login_required
@admin_required
def download_user_template():
    # 建立Excel範本
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    
    # 建立範例資料
    df = pd.DataFrame({
        'username': ['user1', 'user2'],
        'employee_id': ['EMP001', 'EMP002'],
        'full_name': ['王小明', '李小華'],
        'department': ['研發部', '行銷部'],
        'position': ['工程師', '專員'],
        'email': ['user1@example.com', 'user2@example.com'],
        'hire_date': ['2024-01-01', '2024-01-02']
    })
    
    # 寫入Excel
    df.to_excel(writer, sheet_name='使用者資料', index=False)
    
    # 取得工作表以進行格式設定
    workbook = writer.book
    worksheet = writer.sheets['使用者資料']
    
    # 設定欄寬
    worksheet.set_column('A:G', 15)
    
    # 添加標題格式
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#D9E1F2',
        'border': 1
    })
    
    # 為每個欄位添加標題格式
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(0, col_num, value, header_format)
    
    # 添加說明工作表
    instruction_sheet = workbook.add_worksheet('填寫說明')
    instruction_sheet.set_column('A:B', 30)
    
    # 設定說明格式
    title_format = workbook.add_format({
        'bold': True,
        'font_size': 12,
        'bg_color': '#D9E1F2'
    })
    content_format = workbook.add_format({
        'text_wrap': True,
        'valign': 'top'
    })
    
    # 寫入說明內容
    instructions = [
        ['欄位', '說明'],
        ['username', '使用者登入帳號（必填）'],
        ['employee_id', '員工編號（必填，將作為預設密碼）'],
        ['full_name', '員工姓名（必填）'],
        ['department', '部門名稱（必填）'],
        ['position', '職位名稱（必填）'],
        ['email', '電子郵件（選填）'],
        ['hire_date', '到職日期（選填，格式：YYYY-MM-DD）']
    ]
    
    for row_num, instruction in enumerate(instructions):
        instruction_sheet.write(row_num, 0, instruction[0], title_format if row_num == 0 else content_format)
        instruction_sheet.write(row_num, 1, instruction[1], title_format if row_num == 0 else content_format)
    
    writer.close()
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='user_template.xlsx'
    )

# 統計分析相關路由
@app.route('/admin/statistics', methods=['GET', 'POST'])
@login_required
@admin_required
def statistics():
    # 獲取分析參數
    analysis_type = request.form.get('analysis_type', 'overall')
    time_range = request.form.get('time_range', 'all')
    department_id = request.form.get('department', '')
    user_id = request.form.get('user', '')

    # 基礎查詢
    query = Feedback.query

    # 根據時間範圍過濾
    if time_range != 'all':
        now = datetime.now()
        if time_range == 'month':
            query = query.filter(Feedback.created_at >= now.replace(day=1))
        elif time_range == 'quarter':
            query = query.filter(Feedback.created_at >= now.replace(month=((now.month-1)//3)*3+1, day=1))
        elif time_range == 'year':
            query = query.filter(Feedback.created_at >= now.replace(month=1, day=1))

    # 根據部門過濾
    if department_id:
        query = query.join(User, Feedback.target_id == User.id).filter(User.department_id == department_id)

    # 根據用戶過濾
    if user_id:
        query = query.filter(Feedback.target_id == user_id)

    # 獲取所有部門列表
    departments = Department.query.all()

    # 獲取所有用戶列表（用於個人分析）
    users = User.query.filter_by(is_admin=False).all()

    # 計算問卷完成率（根據篩選條件）
    filtered_total = query.count()
    filtered_completed = query.filter_by(status='completed').count()
    completion_rate = {
        'completed': filtered_completed,
        'pending': filtered_total - filtered_completed
    }

    # 定義評估維度
    dimensions = {
        'work_quality': '工作品質',
        'work_efficiency': '工作效率',
        'work_reliability': '工作可靠度',
        'leadership': '領導能力',
        'decision_making': '決策能力',
        'team_management': '團隊管理',
        'collaboration': '協作能力',
        'interpersonal_skills': '人際關係',
        'conflict_resolution': '衝突處理',
        'communication_skills': '溝通技巧',
        'presentation_skills': '表達能力',
        'listening_skills': '傾聽能力'
    }

    # 計算各維度平均分數（根據篩選條件）
    dimension_scores = []
    dimension_labels = []
    overall_scores = []  # 新增：用於存儲整體平均值
    for field, label in dimensions.items():
        avg_score = db.session.query(func.avg(getattr(Feedback, field))).filter(
            Feedback.id.in_([f.id for f in query.all()])
        ).scalar() or 0
        dimension_scores.append(float(avg_score))
        dimension_labels.append(label)
        
        # 計算整體平均值
        overall_avg = db.session.query(func.avg(getattr(Feedback, field))).filter(
            getattr(Feedback, field).isnot(None)
        ).scalar() or 0
        overall_scores.append(float(overall_avg))

    # 計算詳細統計數據（根據篩選條件）
    detailed_stats = []
    filtered_feedbacks = query.all()
    for field, label in dimensions.items():
        scores = [getattr(f, field) for f in filtered_feedbacks if getattr(f, field) is not None]
        if scores:
            stats = {
                'name': label,
                'average': np.mean(scores),
                'max': max(scores),
                'min': min(scores),
                'std_dev': np.std(scores),
                'sample_size': len(scores)
            }
            detailed_stats.append(stats)

    # 獲取個人分析數據
    personal_analysis = None
    if user_id:
        user = User.query.get(user_id)
        if user:
            personal_feedbacks = Feedback.query.filter_by(target_id=user_id).all()
            personal_analysis = {
                'user': user,
                'total_feedbacks': len(personal_feedbacks),
                'completed_feedbacks': len([f for f in personal_feedbacks if f.status == 'completed']),
                'average_scores': {}
            }
            
            for field, label in dimensions.items():
                scores = [getattr(f, field) for f in personal_feedbacks if getattr(f, field) is not None]
                if scores:
                    personal_analysis['average_scores'][label] = {
                        'average': np.mean(scores),
                        'max': max(scores),
                        'min': min(scores),
                        'std_dev': np.std(scores),
                        'sample_size': len(scores)
                    }

    # 計算落點分析數據
    scatter_plot_data = []
    for user in users:
        user_feedbacks = Feedback.query.filter_by(target_id=user.id).all()
        if user_feedbacks:
            user_scores = {}
            for field, label in dimensions.items():
                scores = [getattr(f, field) for f in user_feedbacks if getattr(f, field) is not None]
                if scores:
                    user_scores[label] = np.mean(scores)
            
            if user_scores:
                scatter_plot_data.append({
                    'username': user.username,
                    'department': user.department.name if user.department else '未分配部門',
                    'scores': user_scores
                })

    return render_template('admin/statistics.html',
                         departments=departments,
                         users=users,
                         completion_rate=completion_rate,
                         dimension_labels=dimension_labels,
                         dimension_scores=dimension_scores,
                         overall_scores=overall_scores,  # 新增：傳遞整體平均值列表
                         detailed_stats=detailed_stats,
                         selected_department=department_id,
                         selected_time_range=time_range,
                         selected_analysis_type=analysis_type,
                         selected_user=user_id,
                         personal_analysis=personal_analysis,
                         scatter_plot_data=scatter_plot_data)

@app.route('/admin/users/batch_upload', methods=['POST'])
@login_required
@admin_required
def batch_upload_users():
    if 'file' not in request.files:
        flash('未選擇檔案', 'error')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('未選擇檔案', 'error')
        return redirect(url_for('admin_dashboard'))

    if not file.filename.endswith('.xlsx'):
        flash('請上傳 Excel 檔案 (.xlsx)', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        # 讀取Excel檔案
        df = pd.read_excel(file)
        success_count = 0
        error_messages = []

        for index, row in df.iterrows():
            try:
                # 檢查必要欄位
                if not all(field in row for field in ['username', 'employee_id', 'full_name', 'department', 'position']):
                    error_messages.append(f'第 {index + 2} 行: 缺少必要欄位')
                    continue

                # 檢查部門是否存在
                department = Department.query.filter_by(name=row['department']).first()
                if not department:
                    department = Department(name=row['department'])
                    db.session.add(department)
                    db.session.flush()

                # 檢查使用者是否已存在
                existing_user = User.query.filter(
                    (User.username == row['username']) | 
                    (User.employee_id == str(row['employee_id']))
                ).first()

                if existing_user:
                    error_messages.append(f'第 {index + 2} 行: 使用者名稱或員工編號已存在')
                    continue

                # 建立新使用者
                hire_date = pd.to_datetime(row['hire_date']).date() if 'hire_date' in row else None
                default_password = generate_password_hash(str(row['employee_id']))  # 使用員工編號作為預設密碼

                new_user = User(
                    username=row['username'],
                    password=default_password,
                    email=row.get('email'),
                    employee_id=str(row['employee_id']),
                    full_name=row['full_name'],
                    position=row['position'],
                    hire_date=hire_date,
                    department_id=department.id,
                    is_active=True
                )
                db.session.add(new_user)
                success_count += 1

            except Exception as e:
                error_messages.append(f'第 {index + 2} 行: {str(e)}')
                continue

        db.session.commit()
        
        if success_count > 0:
            flash(f'成功匯入 {success_count} 位使用者', 'success')
        
        if error_messages:
            flash('部分資料匯入失敗：\n' + '\n'.join(error_messages), 'warning')
            
        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        db.session.rollback()
        flash(f'匯入失敗：{str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 創建測試部門
        departments = ['研發部', '行銷部', '人資部', '財務部']
        for dept_name in departments:
            if not Department.query.filter_by(name=dept_name).first():
                dept = Department(name=dept_name)
                db.session.add(dept)
        
        # 創建管理員帳號
        if not User.query.filter_by(username='David').first():
            admin = User(
                username='David',
                password=generate_password_hash('12345678'),
                is_admin=True,
                department_id=1  # 預設分配到研發部
            )
            db.session.add(admin)
        
        # 創建測試用戶
        test_users = ['user1', 'user2', 'user3', 'user4']
        for i, username in enumerate(test_users):
            if not User.query.filter_by(username=username).first():
                user = User(
                    username=username,
                    password=generate_password_hash('12345678'),
                    is_admin=False,
                    department_id=(i % 4) + 1  # 輪流分配到不同部門
                )
                db.session.add(user)
        
        db.session.commit()
        
        # 為 user1 創建評估任務
        user1 = User.query.filter_by(username='user1').first()
        users_to_evaluate = User.query.filter(User.username.in_(['user2', 'user3', 'user4'])).all()
        
        for target_user in users_to_evaluate:
            existing_feedback = Feedback.query.filter_by(
                evaluator_id=user1.id,
                target_id=target_user.id
            ).first()
            
            if not existing_feedback:
                feedback = Feedback(
                    evaluator_id=user1.id,
                    target_id=target_user.id,
                    status='pending'
                )
                db.session.add(feedback)
        
        db.session.commit()
    
    app.run(debug=True) 