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
from sqlalchemy import func, extract
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random

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
    status = db.Column(db.String(20), default='active')  # 用戶狀態：active, inactive, suspended
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
    status = db.Column(db.String(20), default='pending')  # pending 或 completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
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
    
    # 添加關聯關係
    evaluator = db.relationship('User', foreign_keys=[evaluator_id], backref='evaluated_feedbacks')
    target = db.relationship('User', foreign_keys=[target_id], backref='received_feedbacks')

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
        feedback.completed_at = datetime.utcnow()
        db.session.commit()
        flash('評估表單已成功提交')
        return redirect(url_for('index'))
    return render_template('feedback_form.html', feedback=feedback, User=User)

# 管理者路由
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        # 獲取分析參數
        analysis_type = request.form.get('analysis_type', 'overall')
        time_range = request.form.get('time_range', 'all')
        department_id = request.form.get('department', '')
        user_id = request.form.get('user', '')

        # 基礎查詢
        query = Feedback.query.filter_by(status='completed')

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

        # 獲取篩選後的問卷
        filtered_feedbacks = query.all()

        # 計算問卷完成率
        total_tasks = Feedback.query
        if department_id:
            total_tasks = total_tasks.join(User, Feedback.target_id == User.id).filter(User.department_id == department_id)
        if user_id:
            total_tasks = total_tasks.filter(Feedback.target_id == user_id)

        completion_rate = {
            'completed': len(filtered_feedbacks),
            'pending': total_tasks.filter_by(status='pending').count()
        }

        # 定義評估維度
        dimension_labels = ['領導力', '溝通技巧', '專業知識', '團隊合作', '創新能力']
        dimension_fields = {
            '領導力': ['leadership', 'decision_making', 'team_management'],
            '溝通技巧': ['communication_skills', 'presentation_skills', 'listening_skills'],
            '專業知識': ['technical_knowledge', 'industry_knowledge', 'problem_solving'],
            '團隊合作': ['collaboration', 'interpersonal_skills', 'conflict_resolution'],
            '創新能力': ['innovation', 'creativity', 'adaptability']
        }

        # 計算各維度平均分數
        dimension_scores = []
        overall_scores = []
        detailed_stats = []

        for label, fields in dimension_fields.items():
            scores = []
            for feedback in filtered_feedbacks:
                # 計算該維度的平均分數
                dimension_scores_sum = sum(getattr(feedback, field, 0) or 0 for field in fields)
                dimension_avg = dimension_scores_sum / len(fields) if dimension_scores_sum > 0 else 0
                if dimension_avg > 0:
                    scores.append(dimension_avg)

            if scores:
                avg = sum(scores) / len(scores)
                dimension_scores.append(round(avg, 2))
                overall_scores.append(round(avg, 2))
                
                detailed_stats.append({
                    'name': label,
                    'average': avg,
                    'max': max(scores),
                    'min': min(scores),
                    'std_dev': (sum((x - avg) ** 2 for x in scores) / len(scores)) ** 0.5,
                    'sample_size': len(scores),
                    'trend': [round(avg, 2)]  # 簡化的趨勢數據
                })
            else:
                dimension_scores.append(0)
                overall_scores.append(0)
                detailed_stats.append({
                    'name': label,
                    'average': 0,
                    'max': 0,
                    'min': 0,
                    'std_dev': 0,
                    'sample_size': 0,
                    'trend': [0]
                })

        return jsonify({
            'completion_rate': completion_rate,
            'dimension_labels': dimension_labels,
            'dimension_scores': dimension_scores,
            'overall_scores': overall_scores,
            'detailed_stats': detailed_stats
        })

    # GET請求的原有邏輯
    # 統計卡片數據
    pending_tasks = Feedback.query.filter_by(status='pending').count()
    completed_tasks = Feedback.query.filter_by(status='completed').count()
    active_goals = PerformanceGoal.query.filter_by(status='進行中').count()
    
    # 計算待改善項目數量
    improvement_items = 0
    feedbacks = Feedback.query.filter_by(status='completed').all()
    for feedback in feedbacks:
        if any(score < 3 for score in [
            feedback.leadership,
            feedback.communication_skills,
            feedback.technical_knowledge,
            feedback.collaboration,
            feedback.innovation
        ] if score is not None):
            improvement_items += 1

    # 績效趨勢數據
    performance_trend_data = calculate_performance_trend()
    
    # 部門績效比較數據
    departments = Department.query.all()
    department_names = [dept.name for dept in departments]
    department_scores = calculate_department_scores(departments)
    
    # 目標管理數據
    goals = PerformanceGoal.query.all()
    
    # KPI數據
    kpi_actual_data = []
    kpi_target_data = [80, 85, 95, 70, 90]
    
    # 問卷分析數據
    completed_feedbacks = Feedback.query.filter_by(status='completed').all()
    
    # 問卷完成率
    completion_rate = {
        'completed': completed_tasks,
        'pending': pending_tasks
    }
    
    # 各維度平均分數
    dimension_labels = ['領導力', '溝通技巧', '專業知識', '團隊合作', '創新能力']
    dimension_scores = []
    overall_scores = []
    
    if completed_feedbacks:
        # 計算各維度的平均分數
        dimensions = {
            'leadership': [],
            'communication_skills': [],
            'technical_knowledge': [],
            'collaboration': [],
            'innovation': []
        }
        
        for feedback in completed_feedbacks:
            for dimension in dimensions:
                score = getattr(feedback, dimension)
                if score is not None:
                    dimensions[dimension].append(score)
        
        # 計算每個維度的平均分數
        for dimension in dimensions.values():
            if dimension:
                avg_score = sum(dimension) / len(dimension)
                dimension_scores.append(round(avg_score, 2))
                overall_scores.append(round(avg_score, 2))  # 使用相同的數據作為整體平均
            else:
                dimension_scores.append(0)
                overall_scores.append(0)
    
    # 詳細統計數據
    detailed_stats = []
    if completed_feedbacks:
        for dimension, label in zip(['leadership', 'communication_skills', 'technical_knowledge', 'collaboration', 'innovation'], dimension_labels):
            scores = [getattr(f, dimension) for f in completed_feedbacks if getattr(f, dimension) is not None]
            if scores:
                avg = sum(scores) / len(scores)
                max_score = max(scores)
                min_score = min(scores)
                std_dev = (sum((x - avg) ** 2 for x in scores) / len(scores)) ** 0.5
                detailed_stats.append({
                    'name': label,
                    'average': avg,
                    'max': max_score,
                    'min': min_score,
                    'std_dev': std_dev,
                    'sample_size': len(scores)
                })
    
    # 落點分析數據
    scatter_plot_data = []
    if completed_feedbacks:
        for feedback in completed_feedbacks:
            if feedback.leadership is not None and feedback.communication_skills is not None:
                scatter_plot_data.append({
                    'label': f"{feedback.evaluator.full_name} → {feedback.target.full_name}",
                    'data': [{
                        'x': feedback.leadership,
                        'y': feedback.communication_skills
                    }],
                    'backgroundColor': 'rgba(54, 162, 235, 0.5)'
                })
    
    # 待改善項目列表
    improvement_list = get_improvement_items()
    
    # 問卷任務列表
    feedback_tasks = get_feedback_tasks()
    
    return render_template('admin/dashboard.html',
        pending_tasks=pending_tasks,
        completed_tasks=completed_tasks,
        active_goals=active_goals,
        improvement_items=improvement_items,
        performance_trend_data=performance_trend_data,
        department_names=department_names,
        department_scores=department_scores,
        goals=goals,
        kpi_actual_data=kpi_actual_data,
        kpi_target_data=kpi_target_data,
        improvement_list=improvement_list,
        feedback_tasks=feedback_tasks,
        users=User.query.all(),
        # 問卷分析數據
        completion_rate=completion_rate,
        dimension_labels=dimension_labels,
        dimension_scores=dimension_scores,
        overall_scores=overall_scores,
        detailed_stats=detailed_stats,
        scatter_plot_data=scatter_plot_data
    )

def calculate_performance_trend():
    """計算季度績效趨勢"""
    current_year = datetime.now().year
    quarters = {
        1: [1, 2, 3],
        2: [4, 5, 6],
        3: [7, 8, 9],
        4: [10, 11, 12]
    }
    
    trend_data = []
    for quarter, months in quarters.items():
        feedbacks = Feedback.query.filter(
            Feedback.status == 'completed',
            extract('year', Feedback.created_at) == current_year,
            extract('month', Feedback.created_at).in_(months)
        ).all()
        
        if feedbacks:
            quarter_scores = []
            for feedback in feedbacks:
                scores = [
                    feedback.leadership,
                    feedback.communication_skills,
                    feedback.technical_knowledge,
                    feedback.collaboration,
                    feedback.innovation
                ]
                avg_score = sum(filter(None, scores)) / len([s for s in scores if s is not None])
                quarter_scores.append(avg_score)
            
            trend_data.append(round(sum(quarter_scores) / len(quarter_scores), 2))
        else:
            trend_data.append(0)
    
    return trend_data

def calculate_department_scores(departments):
    """計算各部門平均績效分數"""
    department_scores = []
    
    for dept in departments:
        feedbacks = Feedback.query.join(
            User, Feedback.target_id == User.id
        ).filter(
            User.department_id == dept.id,
            Feedback.status == 'completed'
        ).all()
        
        if feedbacks:
            dept_scores = []
            for feedback in feedbacks:
                scores = [
                    feedback.leadership,
                    feedback.communication_skills,
                    feedback.technical_knowledge,
                    feedback.collaboration,
                    feedback.innovation
                ]
                avg_score = sum(filter(None, scores)) / len([s for s in scores if s is not None])
                dept_scores.append(avg_score)
            
            department_scores.append(round(sum(dept_scores) / len(dept_scores), 2))
        else:
            department_scores.append(0)
    
    return department_scores

def get_improvement_items():
    """獲取需要改善的項目列表"""
    improvement_items = []
    feedbacks = Feedback.query.filter_by(status='completed').all()
    
    for feedback in feedbacks:
        scores = {
            'leadership': (feedback.leadership, '領導能力'),
            'communication': (feedback.communication_skills, '溝通技巧'),
            'technical': (feedback.technical_knowledge, '專業知識'),
            'collaboration': (feedback.collaboration, '團隊合作'),
            'innovation': (feedback.innovation, '創新能力')
        }
        
        for key, (score, name) in scores.items():
            if score and score < 3:
                target_user = User.query.get(feedback.target_id)
                improvement_items.append({
                    'employee_name': target_user.full_name,
                    'department': target_user.department.name if target_user.department else '未分配',
                    'item': name,
                    'suggestion': f'建議加強{name}相關培訓',
                    'status': '進行中',
                    'status_color': 'warning'
                })
    
    return improvement_items

def get_feedback_tasks():
    """獲取問卷任務列表"""
    tasks = []
    feedbacks = Feedback.query.join(
        User, Feedback.evaluator_id == User.id
    ).join(
        User, Feedback.target_id == User.id, aliased=True
    ).all()
    
    for feedback in feedbacks:
        evaluator = User.query.get(feedback.evaluator_id)
        target = User.query.get(feedback.target_id)
        
        if evaluator and target:
            tasks.append({
                'id': feedback.id,
                'evaluator': evaluator,
                'target': target,
                'status': '已完成' if feedback.status == 'completed' else '進行中',
                'created_at': feedback.created_at,
                'completed_at': feedback.completed_at if feedback.status == 'completed' else None
            })
    
    return tasks

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

@app.route('/admin/feedback/download_template')
@login_required
@admin_required
def download_feedback_template():
    """下載評估任務匯入範本"""
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    workbook = writer.book
    
    # 建立範本工作表
    template_sheet = workbook.add_worksheet('範本')
    
    # 設定格式
    title_format = workbook.add_format({
        'bold': True,
        'font_size': 12,
        'bg_color': '#D9E1F2',
        'border': 1
    })
    
    content_format = workbook.add_format({
        'border': 1
    })
    
    # 寫入標題
    headers = ['評估者員工編號', '受評者員工編號']
    for col, header in enumerate(headers):
        template_sheet.write(0, col, header, title_format)
    
    # 寫入說明
    instructions = [
        ['評估者員工編號', '評估者的員工編號（必填）'],
        ['受評者員工編號', '受評者的員工編號（必填）']
    ]
    
    for row_num, instruction in enumerate(instructions):
        template_sheet.write(row_num + 2, 0, instruction[0], title_format if row_num == 0 else content_format)
        template_sheet.write(row_num + 2, 1, instruction[1], title_format if row_num == 0 else content_format)
    
    writer.close()
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='feedback_template.xlsx'
    )

@app.route('/admin/feedback/upload', methods=['POST'])
@login_required
@admin_required
def upload_feedback_csv():
    """上傳評估任務CSV檔案"""
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
        required_headers = ['評估者員工編號', '受評者員工編號']
        if not all(header in csv_data.fieldnames for header in required_headers):
            flash('CSV檔案格式錯誤，請使用正確的範本')
            return redirect(url_for('admin_dashboard'))
        
        # 處理每一行資料
        success_count = 0
        error_count = 0
        error_messages = []
        
        for row in csv_data:
            try:
                # 查找評估者和受評者
                evaluator = User.query.filter_by(employee_id=row['評估者員工編號']).first()
                target = User.query.filter_by(employee_id=row['受評者員工編號']).first()
                
                if not evaluator:
                    raise ValueError(f"找不到評估者：{row['評估者員工編號']}")
                if not target:
                    raise ValueError(f"找不到受評者：{row['受評者員工編號']}")
                
                # 檢查是否已存在相同的評估任務
                existing_feedback = Feedback.query.filter_by(
                    evaluator_id=evaluator.id,
                    target_id=target.id
                ).first()
                
                if existing_feedback:
                    raise ValueError(f"已存在相同的評估任務：{evaluator.full_name} -> {target.full_name}")
                
                # 建立新的評估任務
                feedback = Feedback(
                    evaluator_id=evaluator.id,
                    target_id=target.id,
                    status='pending'
                )
                db.session.add(feedback)
                success_count += 1
                
            except ValueError as e:
                error_count += 1
                error_messages.append(str(e))
        
        db.session.commit()
        
        # 顯示結果訊息
        if success_count > 0:
            flash(f'成功匯入 {success_count} 筆評估任務')
        if error_count > 0:
            flash(f'匯入失敗 {error_count} 筆：' + '；'.join(error_messages))
        
    except Exception as e:
        db.session.rollback()
        flash(f'匯入失敗：{str(e)}')
    
    return redirect(url_for('admin_dashboard'))

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
        'pending': filtered_total - filtered_completed,
        'completion_percentage': 0.0  # 預設值
    }
    
    # 計算完成率百分比（避免除以零）
    if filtered_total > 0:
        completion_rate['completion_percentage'] = (filtered_completed / filtered_total) * 100

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
                'completion_percentage': 0.0,  # 預設值
                'average_scores': {}
            }
            
            # 計算個人完成率百分比（避免除以零）
            if personal_analysis['total_feedbacks'] > 0:
                personal_analysis['completion_percentage'] = (personal_analysis['completed_feedbacks'] / personal_analysis['total_feedbacks']) * 100
            
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
                         overall_scores=overall_scores,
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

# 使用者更新路由
@app.route('/admin/user/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user_inline(user_id):
    user = User.query.get_or_404(user_id)
    
    try:
        # 更新使用者資料
        if 'employee_id' in request.form:
            user.employee_id = request.form['employee_id']
        if 'full_name' in request.form:
            user.full_name = request.form['full_name']
        if 'department_id' in request.form:
            user.department_id = request.form['department_id']
        if 'position' in request.form:
            user.position = request.form['position']
        if 'is_active' in request.form:
            user.is_active = request.form['is_active'] == '1'
        
        db.session.commit()
        
        # 返回更新後的資料
        return jsonify({
            'employee_id': user.employee_id,
            'full_name': user.full_name,
            'department_name': user.department.name if user.department else '未分配',
            'position': user.position,
            'is_active': user.is_active
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/admin/performance_trend')
@login_required
@admin_required
def performance_trend():
    # 獲取所有評估數據
    feedbacks = Feedback.query.filter_by(status='completed').all()
    
    # 按季度整理數據
    quarterly_data = {
        'Q1': [], 'Q2': [], 'Q3': [], 'Q4': []
    }
    
    for feedback in feedbacks:
        quarter = (feedback.created_at.month - 1) // 3 + 1
        q_key = f'Q{quarter}'
        
        # 計算平均分數（使用正確的屬性名稱）
        scores = [
            feedback.leadership,
            feedback.communication_skills,
            feedback.technical_knowledge,
            feedback.collaboration,
            feedback.innovation
        ]
        avg_score = sum(filter(None, scores)) / len([s for s in scores if s is not None])
        quarterly_data[q_key].append(avg_score)
    
    # 計算每季平均
    trend_data = {
        quarter: round(sum(scores) / len(scores), 2) if scores else 0
        for quarter, scores in quarterly_data.items()
    }
    
    return render_template('admin/performance_trend.html', trend_data=trend_data)

@app.route('/admin/department_comparison')
@login_required
@admin_required
def department_comparison():
    # 獲取所有部門
    departments = Department.query.all()
    department_data = {}
    
    for dept in departments:
        # 獲取部門所有員工的評估數據
        dept_feedbacks = Feedback.query.join(User, Feedback.target_id == User.id)\
            .filter(User.department_id == dept.id, Feedback.status == 'completed').all()
        
        if dept_feedbacks:
            dept_scores = []
            for feedback in dept_feedbacks:
                scores = [
                    feedback.leadership,
                    feedback.communication_skills,
                    feedback.technical_knowledge,
                    feedback.collaboration,
                    feedback.innovation
                ]
                avg_score = sum(filter(None, scores)) / len([s for s in scores if s is not None])
                dept_scores.append(avg_score)
            
            department_data[dept.name] = round(sum(dept_scores) / len(dept_scores), 2)
        else:
            department_data[dept.name] = 0
    
    return render_template('admin/department_comparison.html', department_data=department_data)

@app.route('/admin/goal_management')
@login_required
@admin_required
def goal_management():
    goals = PerformanceGoal.query.all()
    users = User.query.all()
    return render_template('admin/goal_management.html', goals=goals, users=users)

@app.route('/admin/goals/create', methods=['POST'])
@login_required
@admin_required
def create_goal():
    try:
        form_data = request.form
        
        goal = PerformanceGoal(
            description=form_data['description'],
            assignee_id=form_data['assignee'],
            goal_type=form_data['goal_type'],
            start_date=datetime.strptime(form_data['start_date'], '%Y-%m-%d').date(),
            target_date=datetime.strptime(form_data['target_date'], '%Y-%m-%d').date()
        )
        
        db.session.add(goal)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/goals/<int:goal_id>/delete', methods=['DELETE'])
@login_required
@admin_required
def delete_goal(goal_id):
    try:
        goal = PerformanceGoal.query.get_or_404(goal_id)
        db.session.delete(goal)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/goals/<int:goal_id>/update', methods=['POST'])
@login_required
@admin_required
def update_goal(goal_id):
    try:
        goal = PerformanceGoal.query.get_or_404(goal_id)
        form_data = request.form
        
        goal.description = form_data.get('description', goal.description)
        goal.progress = int(form_data.get('progress', goal.progress))
        goal.status = form_data.get('status', goal.status)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# 新增績效目標模型
class PerformanceGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    target_date = db.Column(db.DateTime, nullable=False)
    goal_type = db.Column(db.String(20), nullable=False)  # 個人、部門、公司
    status = db.Column(db.String(20), nullable=False)  # 進行中、已完成、已逾期
    progress = db.Column(db.Integer, default=0)  # 進度百分比
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    assignee = db.relationship('User', backref='performance_goals')

    @property
    def type_color(self):
        return {
            '個人': 'info',
            '部門': 'primary',
            '公司': 'success'
        }.get(self.goal_type, 'secondary')
    
    @property
    def status_color(self):
        return {
            '進行中': 'primary',
            '已完成': 'success',
            '已逾期': 'danger'
        }.get(self.status, 'secondary')

@app.route('/admin/feedback/<int:feedback_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    evaluator = User.query.get(feedback.evaluator_id)
    target = User.query.get(feedback.target_id)
    
    if request.method == 'POST':
        # 更新評估數據
        feedback.work_quality = request.form.get('work_quality', type=int)
        feedback.work_efficiency = request.form.get('work_efficiency', type=int)
        feedback.work_reliability = request.form.get('work_reliability', type=int)
        
        feedback.leadership = request.form.get('leadership', type=int)
        feedback.decision_making = request.form.get('decision_making', type=int)
        feedback.team_management = request.form.get('team_management', type=int)
        
        feedback.collaboration = request.form.get('collaboration', type=int)
        feedback.interpersonal_skills = request.form.get('interpersonal_skills', type=int)
        feedback.conflict_resolution = request.form.get('conflict_resolution', type=int)
        
        feedback.communication_skills = request.form.get('communication_skills', type=int)
        feedback.presentation_skills = request.form.get('presentation_skills', type=int)
        feedback.listening_skills = request.form.get('listening_skills', type=int)
        
        feedback.technical_knowledge = request.form.get('technical_knowledge', type=int)
        feedback.industry_knowledge = request.form.get('industry_knowledge', type=int)
        feedback.problem_solving = request.form.get('problem_solving', type=int)
        
        feedback.work_attitude = request.form.get('work_attitude', type=int)
        feedback.initiative = request.form.get('initiative', type=int)
        feedback.responsibility = request.form.get('responsibility', type=int)
        
        feedback.innovation = request.form.get('innovation', type=int)
        feedback.creativity = request.form.get('creativity', type=int)
        feedback.adaptability = request.form.get('adaptability', type=int)
        
        feedback.analytical_thinking = request.form.get('analytical_thinking', type=int)
        feedback.solution_implementation = request.form.get('solution_implementation', type=int)
        feedback.risk_management = request.form.get('risk_management', type=int)
        
        # 更新文字回饋
        feedback.strengths = request.form.get('strengths')
        feedback.improvements = request.form.get('improvements')
        feedback.suggestions = request.form.get('suggestions')
        
        # 更新狀態
        feedback.status = request.form.get('status', 'pending')
        if feedback.status == 'completed':
            feedback.completed_at = datetime.utcnow()
        
        db.session.commit()
        flash('評估任務已成功更新')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/edit_feedback.html', 
                         feedback=feedback,
                         evaluator=evaluator,
                         target=target)

@app.route('/admin/feedback/<int:feedback_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('評估任務已成功刪除')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/simulate_feedback', methods=['POST'])
@login_required
@admin_required
def simulate_feedback():
    try:
        # 獲取所有在職使用者
        users = User.query.filter_by(is_active=True).all()
        
        # 為每個使用者創建評估任務
        for evaluator in users:
            for target in users:
                if evaluator != target:  # 不允許自我評估
                    # 檢查是否已存在相同的評估任務
                    existing_feedback = Feedback.query.filter_by(
                        evaluator_id=evaluator.id,
                        target_id=target.id
                    ).first()
                    
                    if not existing_feedback:
                        # 創建新的評估任務
                        feedback = Feedback(
                            evaluator_id=evaluator.id,
                            target_id=target.id,
                            status='completed',
                            completed_at=datetime.now(),
                            # 模擬評估分數（1-5分）
                            work_quality=random.randint(3, 5),
                            work_efficiency=random.randint(3, 5),
                            work_reliability=random.randint(3, 5),
                            leadership=random.randint(3, 5),
                            decision_making=random.randint(3, 5),
                            team_management=random.randint(3, 5),
                            collaboration=random.randint(3, 5),
                            interpersonal_skills=random.randint(3, 5),
                            conflict_resolution=random.randint(3, 5),
                            communication_skills=random.randint(3, 5),
                            presentation_skills=random.randint(3, 5),
                            listening_skills=random.randint(3, 5),
                            technical_knowledge=random.randint(3, 5),
                            industry_knowledge=random.randint(3, 5),
                            problem_solving=random.randint(3, 5),
                            work_attitude=random.randint(3, 5),
                            initiative=random.randint(3, 5),
                            responsibility=random.randint(3, 5),
                            innovation=random.randint(3, 5),
                            creativity=random.randint(3, 5),
                            adaptability=random.randint(3, 5),
                            analytical_thinking=random.randint(3, 5),
                            solution_implementation=random.randint(3, 5),
                            risk_management=random.randint(3, 5),
                            # 模擬文字回饋
                            strengths=f"{target.full_name}在{random.choice(['工作能力', '團隊合作', '專業知識'])}方面表現出色。",
                            improvements=f"建議在{random.choice(['溝通技巧', '時間管理', '創新思維'])}方面可以進一步提升。",
                            suggestions=f"建議多參與{random.choice(['跨部門專案', '專業培訓', '團隊活動'])}以提升能力。"
                        )
                        db.session.add(feedback)
        
        db.session.commit()
        flash('模擬問卷填寫完成！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'模擬過程中發生錯誤：{str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/analysis', methods=['GET', 'POST'])
@login_required
@admin_required
def feedback_analysis():
    # 獲取篩選參數
    selected_analysis_type = request.form.get('analysis_type', 'overall')
    selected_time_range = request.form.get('time_range', 'all')
    selected_department = request.form.get('department', '')
    selected_user = request.form.get('user', '')

    # 獲取所有部門和用戶
    departments = Department.query.all()
    users = User.query.all()

    # 基礎查詢
    query = Feedback.query.filter_by(status='completed')

    # 根據時間範圍過濾
    if selected_time_range != 'all':
        now = datetime.now()
        if selected_time_range == 'month':
            query = query.filter(Feedback.created_at >= now.replace(day=1))
        elif selected_time_range == 'quarter':
            query = query.filter(Feedback.created_at >= now.replace(month=((now.month-1)//3)*3+1, day=1))
        elif selected_time_range == 'year':
            query = query.filter(Feedback.created_at >= now.replace(month=1, day=1))

    # 根據部門過濾
    if selected_department:
        query = query.join(User, Feedback.target_id == User.id).filter(User.department_id == selected_department)

    # 根據用戶過濾
    if selected_user:
        query = query.filter(Feedback.target_id == selected_user)

    # 獲取篩選後的問卷
    filtered_feedbacks = query.all()

    # 計算問卷完成率
    total_tasks = Feedback.query
    if selected_department:
        total_tasks = total_tasks.join(User, Feedback.target_id == User.id).filter(User.department_id == selected_department)
    if selected_user:
        total_tasks = total_tasks.filter(Feedback.target_id == selected_user)

    completion_rate = {
        'completed': len(filtered_feedbacks),
        'pending': total_tasks.filter_by(status='pending').count()
    }

    # 定義評估維度
    dimension_labels = ['領導力', '溝通技巧', '專業知識', '團隊合作', '創新能力']
    dimension_fields = {
        '領導力': ['leadership', 'decision_making', 'team_management'],
        '溝通技巧': ['communication_skills', 'presentation_skills', 'listening_skills'],
        '專業知識': ['technical_knowledge', 'industry_knowledge', 'problem_solving'],
        '團隊合作': ['collaboration', 'interpersonal_skills', 'conflict_resolution'],
        '創新能力': ['innovation', 'creativity', 'adaptability']
    }

    # 計算各維度平均分數
    dimension_scores = []
    overall_scores = []
    detailed_stats = []

    for label, fields in dimension_fields.items():
        scores = []
        for feedback in filtered_feedbacks:
            # 計算該維度的平均分數
            dimension_scores_sum = sum(getattr(feedback, field, 0) or 0 for field in fields)
            dimension_avg = dimension_scores_sum / len(fields) if dimension_scores_sum > 0 else 0
            if dimension_avg > 0:
                scores.append(dimension_avg)

        if scores:
            avg = sum(scores) / len(scores)
            dimension_scores.append(round(avg, 2))
            overall_scores.append(round(avg, 2))
            
            detailed_stats.append({
                'name': label,
                'average': avg,
                'max': max(scores),
                'min': min(scores),
                'std_dev': (sum((x - avg) ** 2 for x in scores) / len(scores)) ** 0.5,
                'sample_size': len(scores),
                'trend': [round(avg, 2)]  # 簡化的趨勢數據
            })
        else:
            dimension_scores.append(0)
            overall_scores.append(0)
            detailed_stats.append({
                'name': label,
                'average': 0,
                'max': 0,
                'min': 0,
                'std_dev': 0,
                'sample_size': 0,
                'trend': [0]
            })

    # 準備落點分析數據
    scatter_plot_data = []
    if selected_analysis_type == 'scatter':
        for feedback in filtered_feedbacks:
            user = User.query.get(feedback.target_id)
            if user:
                scores = {}
                for label, fields in dimension_fields.items():
                    dimension_scores_sum = sum(getattr(feedback, field, 0) or 0 for field in fields)
                    dimension_avg = dimension_scores_sum / len(fields) if dimension_scores_sum > 0 else 0
                    scores[label] = round(dimension_avg, 2)
                
                scatter_plot_data.append({
                    'username': user.username,
                    'department': user.department.name if user.department else '未分配部門',
                    'scores': scores
                })

    # 準備個人分析數據
    personal_analysis = None
    if selected_analysis_type == 'personal' and selected_user:
        user = User.query.get(selected_user)
        if user:
            user_feedbacks = query.filter_by(target_id=selected_user).all()
            average_scores = {}
            
            for label, fields in dimension_fields.items():
                scores = []
                for feedback in user_feedbacks:
                    dimension_scores_sum = sum(getattr(feedback, field, 0) or 0 for field in fields)
                    dimension_avg = dimension_scores_sum / len(fields) if dimension_scores_sum > 0 else 0
                    if dimension_avg > 0:
                        scores.append(dimension_avg)
                
                if scores:
                    avg = sum(scores) / len(scores)
                    average_scores[label] = {
                        'average': avg,
                        'max': max(scores),
                        'min': min(scores),
                        'std_dev': (sum((x - avg) ** 2 for x in scores) / len(scores)) ** 0.5,
                        'sample_size': len(scores)
                    }
                else:
                    average_scores[label] = {
                        'average': 0,
                        'max': 0,
                        'min': 0,
                        'std_dev': 0,
                        'sample_size': 0
                    }
            
            personal_analysis = {
                'user': user,
                'total_feedbacks': len(user_feedbacks),
                'completed_feedbacks': len([f for f in user_feedbacks if f.status == 'completed']),
                'average_scores': average_scores
            }

    return render_template('admin/feedback_analysis.html',
                         selected_analysis_type=selected_analysis_type,
                         selected_time_range=selected_time_range,
                         selected_department=selected_department,
                         selected_user=selected_user,
                         departments=departments,
                         users=users,
                         completion_rate=completion_rate,
                         dimension_labels=dimension_labels,
                         dimension_scores=dimension_scores,
                         overall_scores=overall_scores,
                         detailed_stats=detailed_stats,
                         scatter_plot_data=scatter_plot_data,
                         personal_analysis=personal_analysis)

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
                employee_id='EMP001',
                full_name='David Chen',
                position='系統管理員',
                department_id=1  # 預設分配到研發部
            )
            db.session.add(admin)
        
        # 創建測試用戶
        test_users = [
            {
                'username': 'user1',
                'employee_id': 'EMP002',
                'full_name': '王小明',
                'position': '工程師',
                'department_id': 1
            },
            {
                'username': 'user2',
                'employee_id': 'EMP003',
                'full_name': '李小華',
                'position': '專員',
                'department_id': 2
            },
            {
                'username': 'user3',
                'employee_id': 'EMP004',
                'full_name': '張小美',
                'position': '主管',
                'department_id': 3
            },
            {
                'username': 'user4',
                'employee_id': 'EMP005',
                'full_name': '陳小強',
                'position': '經理',
                'department_id': 4
            }
        ]
        
        for user_data in test_users:
            if not User.query.filter_by(username=user_data['username']).first():
                user = User(
                    username=user_data['username'],
                    password=generate_password_hash('12345678'),
                    is_admin=False,
                    employee_id=user_data['employee_id'],
                    full_name=user_data['full_name'],
                    position=user_data['position'],
                    department_id=user_data['department_id']
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