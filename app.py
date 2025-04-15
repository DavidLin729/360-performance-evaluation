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
import xlsxwriter
from io import BytesIO

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

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if 'password' in kwargs:
            self.set_password(kwargs['password'])

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

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

# 績效目標模型
class PerformanceGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    progress = db.Column(db.Integer, default=0)  # 0-100
    status = db.Column(db.String(20), default='進行中')  # 進行中, 已完成, 已逾期
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 關聯關係
    owner = db.relationship('User', backref='goals')
    department = db.relationship('Department', backref='goals')

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
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
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
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('請輸入帳號和密碼', 'error')
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('帳號不存在', 'error')
            return render_template('login.html')
            
        if not user.is_active:
            flash('此帳號已被停用', 'error')
            return render_template('login.html')
            
        if user.check_password(password):
            login_user(user)
            flash('登入成功', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('home'))
        else:
            flash('密碼錯誤', 'error')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出', 'success')
    return redirect(url_for('login'))

@app.route('/feedback/<int:task_id>/fill', methods=['GET', 'POST'])
@login_required
def fill_feedback(task_id):
    # 獲取問卷任務
    task = Feedback.query.get_or_404(task_id)
    
    # 檢查權限
    if task.evaluator_id != current_user.id:
        flash('您沒有權限填寫此問卷', 'danger')
        return redirect(url_for('home'))
    
    # 如果是 POST 請求，處理表單提交
    if request.method == 'POST':
        try:
            # 更新問卷資料
            for field in request.form:
                if hasattr(task, field) and field not in ['csrf_token']:
                    value = request.form.get(field)
                    if value:
                        if field in ['strengths', 'improvements', 'suggestions']:
                            setattr(task, field, value)
                        else:
                            setattr(task, field, int(value))
            
            # 更新狀態
            task.status = 'completed'
            task.completed_at = datetime.utcnow()
            
            # 儲存到資料庫
            db.session.commit()
            
            flash('問卷已成功提交', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'提交問卷時發生錯誤：{str(e)}', 'danger')
            return render_template('feedback_form.html', task=task)
    
    # GET 請求，顯示問卷表單
    return render_template('feedback_form.html', task=task)

# 管理者路由
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # 統計卡片數據
    pending_tasks = Feedback.query.filter_by(status='pending').count()
    completed_tasks = Feedback.query.filter_by(status='completed').count()
    active_goals = PerformanceGoal.query.filter_by(status='進行中').count()
    
    # 計算待改善項目數量
    improvement_items = 0
    completed_feedbacks = Feedback.query.filter_by(status='completed').all()
    for feedback in completed_feedbacks:
        if feedback.improvements:
            improvement_items += 1
    
    return render_template('admin/dashboard.html',
                         pending_tasks=pending_tasks,
                         completed_tasks=completed_tasks,
                         active_goals=active_goals,
                         improvement_items=improvement_items)

@app.route('/admin/performance')
@login_required
@admin_required
def performance_management():
    # 獲取績效相關數據
    departments = Department.query.all()
    users = User.query.all()
    performance_data = {
        'departments': departments,
        'users': users
    }
    return render_template('admin/performance.html', data=performance_data)

@app.route('/admin/goals')
@login_required
@admin_required
def goal_management():
    # 獲取目標相關數據
    goals = PerformanceGoal.query.all()
    departments = Department.query.all()
    users = User.query.all()
    
    # 計算目標統計數據
    total_goals = len(goals)
    completed_goals = len([g for g in goals if g.status == '已完成'])
    in_progress_goals = len([g for g in goals if g.status == '進行中'])
    overdue_goals = len([g for g in goals if g.status == '已逾期'])
    
    return render_template('admin/goals.html', 
                         goals=goals,
                         departments=departments,
                         users=users,
                         total_goals=total_goals,
                         completed_goals=completed_goals,
                         in_progress_goals=in_progress_goals,
                         overdue_goals=overdue_goals)

@app.route('/admin/feedback')
@login_required
@admin_required
def feedback_management():
    # 獲取問卷任務相關數據
    feedback_tasks = Feedback.query.all()
    users = User.query.all()
    
    # 計算任務統計數據
    total_tasks = len(feedback_tasks)
    completed_tasks = len([t for t in feedback_tasks if t.status == 'completed'])
    in_progress_tasks = len([t for t in feedback_tasks if t.status == 'pending'])
    overdue_tasks = 0  # 目前沒有截止日期，所以暫時設為0
    
    # 準備任務列表數據
    tasks = []
    for task in feedback_tasks:
        target_user = User.query.get(task.target_id)
        evaluator = User.query.get(task.evaluator_id)
        
        # 計算完成率
        if task.status == 'completed':
            completion_rate = 100
        else:
            completion_rate = 0
            
        tasks.append({
            'id': task.id,
            'title': f'{target_user.full_name}的360度評估問卷',
            'target_user': target_user,
            'evaluator': evaluator,
            'start_date': task.created_at,
            'end_date': task.created_at,  # 目前沒有截止日期，暫時使用創建日期
            'completion_rate': completion_rate,
            'status': 'completed' if task.status == 'completed' else 'in_progress'
        })
    
    # 準備數據字典
    data = {
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'in_progress_tasks': in_progress_tasks,
        'overdue_tasks': overdue_tasks,
        'tasks': tasks,
        'users': users
    }
    
    return render_template('admin/feedback.html', data=data)

@app.route('/admin/feedback/analysis', methods=['GET', 'POST'])
@login_required
@admin_required
def feedback_analysis():
    # 獲取所有部門和用戶
    departments = Department.query.all()
    users = User.query.all()
    
    # 初始化篩選條件
    selected_analysis_type = request.form.get('analysis_type', 'overall')
    selected_time_range = request.form.get('time_range', 'all')
    selected_department = request.form.get('department', '')
    selected_user = request.form.get('user', '')
    
    # 獲取所有問卷
    feedback_tasks = Feedback.query.all()
    
    # 計算完成率
    completed = sum(1 for task in feedback_tasks if task.status == 'completed')
    pending = sum(1 for task in feedback_tasks if task.status == 'pending')
    completion_rate = {
        'completed': completed,
        'pending': pending
    }
    
    # 初始化所有必要的變數
    dimension_labels = []
    dimension_scores = []
    detailed_stats = []
    scatter_plot_data = {
        'labels': [],
        'datasets': [{
            'label': '評分分佈',
            'data': [],
            'backgroundColor': 'rgba(75, 192, 192, 0.6)',
            'borderColor': 'rgba(75, 192, 192, 1)',
            'borderWidth': 1
        }]
    }
    personal_analysis = None
    
    # 維度名稱映射
    dimension_mapping = {
        '工作能力': ['work_quality', 'work_efficiency', 'work_reliability'],
        '領導力': ['leadership', 'decision_making', 'team_management'],
        '團隊合作': ['collaboration', 'interpersonal_skills', 'conflict_resolution'],
        '溝通能力': ['communication_skills', 'presentation_skills', 'listening_skills'],
        '專業知識': ['technical_knowledge', 'industry_knowledge', 'problem_solving'],
        '工作態度': ['work_attitude', 'initiative', 'responsibility'],
        '創新思維': ['innovation', 'creativity', 'adaptability'],
        '問題解決': ['analytical_thinking', 'solution_implementation', 'risk_management']
    }
    
    # 根據選擇的分析類型準備數據
    if selected_analysis_type == 'overall':
        # 整體分析
        completed_feedbacks = [f for f in feedback_tasks if f.status == 'completed']
        
        if completed_feedbacks:
            # 計算各維度的平均分數
            dimension_scores = {
                '工作能力': {
                    'work_quality': [],
                    'work_efficiency': [],
                    'work_reliability': []
                },
                '領導力': {
                    'leadership': [],
                    'decision_making': [],
                    'team_management': []
                },
                '團隊合作': {
                    'collaboration': [],
                    'interpersonal_skills': [],
                    'conflict_resolution': []
                },
                '溝通能力': {
                    'communication_skills': [],
                    'presentation_skills': [],
                    'listening_skills': []
                },
                '專業知識': {
                    'technical_knowledge': [],
                    'industry_knowledge': [],
                    'problem_solving': []
                },
                '工作態度': {
                    'work_attitude': [],
                    'initiative': [],
                    'responsibility': []
                },
                '創新思維': {
                    'innovation': [],
                    'creativity': [],
                    'adaptability': []
                },
                '問題解決': {
                    'analytical_thinking': [],
                    'solution_implementation': [],
                    'risk_management': []
                }
            }
            
            # 收集所有分數
            for feedback in completed_feedbacks:
                for dimension, metrics in dimension_scores.items():
                    for metric in metrics:
                        score = getattr(feedback, metric)
                        if score is not None:
                            metrics[metric].append(score)
            
            # 計算各維度的統計數據
            detailed_stats = []
            for dimension, metrics in dimension_scores.items():
                all_scores = []
                for metric_scores in metrics.values():
                    all_scores.extend(metric_scores)
                
                if all_scores:
                    avg = sum(all_scores) / len(all_scores)
                    max_score = max(all_scores)
                    min_score = min(all_scores)
                    std_dev = (sum((x - avg) ** 2 for x in all_scores) / len(all_scores)) ** 0.5
                    
                    detailed_stats.append({
                        'name': dimension,
                        'average': round(avg, 2),
                        'max': max_score,
                        'min': min_score,
                        'std_dev': round(std_dev, 2),
                        'sample_size': len(all_scores),
                        'trend': all_scores
                    })
            
            # 準備圖表數據
            dimension_labels = list(dimension_mapping.keys())
            dimension_scores = []
            for dimension in dimension_labels:
                scores = []
                for feedback in completed_feedbacks:
                    # 獲取該維度下的所有分數
                    dimension_scores_list = []
                    for metric in dimension_mapping[dimension]:
                        score = getattr(feedback, metric)
                        if score is not None and isinstance(score, (int, float)):
                            dimension_scores_list.append(score)
                    if dimension_scores_list:  # 只添加有有效分數的維度
                        scores.append(sum(dimension_scores_list) / len(dimension_scores_list))
                if scores:  # 只添加有有效分數的維度
                    dimension_scores.append(sum(scores) / len(scores))
                else:
                    dimension_scores.append(0)  # 如果沒有有效分數，使用0作為預設值
            
            scatter_plot_data = {
                'labels': dimension_labels,
                'datasets': [{
                    'label': '評分分佈',
                    'data': [{'x': i, 'y': score} for i, score in enumerate(dimension_scores)],
                    'backgroundColor': 'rgba(75, 192, 192, 0.6)',
                    'borderColor': 'rgba(75, 192, 192, 1)',
                    'borderWidth': 1
                }]
            }
    
    elif selected_analysis_type == 'personal' and selected_user:
        # 個人分析
        user = User.query.get(selected_user)
        if user:
            # 獲取該用戶的所有評估結果
            user_feedbacks = Feedback.query.filter_by(target_id=user.id, status='completed').all()
            
            if user_feedbacks:
                # 計算各維度的平均分數
                dimension_scores = {
                    '工作能力': {
                        'work_quality': [],
                        'work_efficiency': [],
                        'work_reliability': []
                    },
                    '領導力': {
                        'leadership': [],
                        'decision_making': [],
                        'team_management': []
                    },
                    '團隊合作': {
                        'collaboration': [],
                        'interpersonal_skills': [],
                        'conflict_resolution': []
                    },
                    '溝通能力': {
                        'communication_skills': [],
                        'presentation_skills': [],
                        'listening_skills': []
                    },
                    '專業知識': {
                        'technical_knowledge': [],
                        'industry_knowledge': [],
                        'problem_solving': []
                    },
                    '工作態度': {
                        'work_attitude': [],
                        'initiative': [],
                        'responsibility': []
                    },
                    '創新思維': {
                        'innovation': [],
                        'creativity': [],
                        'adaptability': []
                    },
                    '問題解決': {
                        'analytical_thinking': [],
                        'solution_implementation': [],
                        'risk_management': []
                    }
                }
                
                # 收集所有分數
                for feedback in user_feedbacks:
                    for dimension, metrics in dimension_scores.items():
                        for metric in metrics:
                            score = getattr(feedback, metric)
                            if score is not None:
                                metrics[metric].append(score)
                
                # 計算各維度的統計數據
                personal_analysis = {
                    'user': user,
                    'total_feedbacks': len(user_feedbacks),
                    'completed_feedbacks': len(user_feedbacks),
                    'average_scores': {}
                }
                
                for dimension, metrics in dimension_scores.items():
                    all_scores = []
                    for metric_scores in metrics.values():
                        all_scores.extend(metric_scores)
                    
                    if all_scores:
                        avg = sum(all_scores) / len(all_scores)
                        max_score = max(all_scores)
                        min_score = min(all_scores)
                        std_dev = (sum((x - avg) ** 2 for x in all_scores) / len(all_scores)) ** 0.5
                        
                        personal_analysis['average_scores'][dimension] = {
                            'average': round(avg, 2),
                            'max': max_score,
                            'min': min_score,
                            'std_dev': round(std_dev, 2),
                            'sample_size': len(all_scores),
                            'trend': all_scores
                        }
                
                # 準備圖表數據
                dimension_labels = list(dimension_mapping.keys())
                dimension_scores = []
                for dimension in dimension_labels:
                    if dimension in personal_analysis['average_scores']:
                        dimension_scores.append(personal_analysis['average_scores'][dimension]['average'])
                    else:
                        dimension_scores.append(0)
                
                scatter_plot_data = {
                    'labels': dimension_labels,
                    'datasets': [{
                        'label': '評分分佈',
                        'data': [{'x': i, 'y': score} for i, score in enumerate(dimension_scores)],
                        'backgroundColor': 'rgba(75, 192, 192, 0.6)',
                        'borderColor': 'rgba(75, 192, 192, 1)',
                        'borderWidth': 1
                    }]
                }
    
    return render_template('admin/feedback_analysis.html',
                         departments=departments,
                         users=users,
                         selected_analysis_type=selected_analysis_type,
                         selected_time_range=selected_time_range,
                         selected_department=selected_department,
                         selected_user=selected_user,
                         completion_rate=completion_rate,
                         dimension_labels=dimension_labels,
                         dimension_scores=dimension_scores,
                         detailed_stats=detailed_stats,
                         scatter_plot_data=scatter_plot_data,
                         personal_analysis=personal_analysis)

@app.route('/admin/users')
@login_required
@admin_required
def user_management():
    # 獲取搜尋和篩選參數
    search = request.args.get('search', '')
    department_id = request.args.get('department', '')
    role = request.args.get('role', '')
    
    # 構建查詢
    query = User.query
    
    if search:
        query = query.filter(
            (User.username.ilike(f'%{search}%')) | 
            (User.email.ilike(f'%{search}%')) |
            (User.full_name.ilike(f'%{search}%'))
        )
    
    if department_id:
        query = query.filter(User.department_id == department_id)
    
    if role:
        query = query.filter(User.role == role)
    
    # 獲取所有部門
    departments = Department.query.all()
    
    # 執行查詢
    users = query.all()
    
    # 準備數據
    data = {
        'users': users,
        'departments': departments,
        'total_users': len(users),
        'active_users': len([u for u in users if u.is_active]),
        'inactive_users': len([u for u in users if not u.is_active]),
        'admin_users': len([u for u in users if u.is_admin])
    }
    
    return render_template('admin/users.html', data=data)

@app.route('/admin/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    try:
        # 檢查請求內容類型
        if not request.is_json and not request.form:
            return jsonify({'success': False, 'message': '無效的請求格式'}), 400

        # 獲取數據（支援both JSON和form-data）
        data = request.get_json() if request.is_json else request.form

        # 驗證必要欄位
        required_fields = ['username', 'full_name', 'email', 'password', 'department_id']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'success': False, 
                'message': f'缺少必要欄位：{", ".join(missing_fields)}'
            }), 400

        # 檢查使用者名稱是否已存在
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'message': '使用者名稱已存在'}), 400
        
        # 檢查電子郵件是否已存在
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': '電子郵件已存在'}), 400
        
        # 建立新使用者
        user = User(
            username=data['username'],
            full_name=data['full_name'],
            email=data['email'],
            department_id=int(data['department_id']),
            is_admin=data.get('is_admin') == 'on',
            is_active=True
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': '使用者建立成功',
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email
            }
        })
        
    except ValueError as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'資料格式錯誤：{str(e)}'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'建立使用者時發生錯誤：{str(e)}'}), 500

@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.form

        # 檢查使用者名稱是否已被其他使用者使用
        if data['username'] != user.username:
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': '使用者名稱已存在'})

        # 檢查電子郵件是否已被其他使用者使用
        if data['email'] != user.email:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': '電子郵件已存在'})

        # 更新使用者資料
        user.username = data['username']
        user.full_name = data['full_name']
        user.email = data['email']
        user.department_id = int(data['department_id'])
        user.is_admin = data.get('is_admin') == 'on'
        user.is_active = data.get('is_active') == 'on'

        # 如果密碼欄位有值，則更新密碼
        if data.get('password'):
            user.set_password(data['password'])

        db.session.commit()
        return jsonify({'success': True, 'message': '使用者更新成功'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新使用者時發生錯誤：{str(e)}'})

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # 檢查是否為最後一個管理員
    if user.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        flash('無法刪除最後一個管理員', 'danger')
        return redirect(url_for('user_management'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash('使用者刪除成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash('刪除使用者時發生錯誤', 'danger')
    
    return redirect(url_for('user_management'))

@app.route('/admin/users/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email,
                'department_id': user.department_id,
                'is_admin': user.is_admin,
                'is_active': user.is_active
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

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

@app.route('/admin/feedback/create', methods=['POST'])
@login_required
@admin_required
def create_feedback():
    try:
        data = request.get_json()
        
        # 檢查必要欄位
        if not data.get('evaluator_id') or not data.get('target_id'):
            return jsonify({'success': False, 'message': '請選擇評分者和被評者'})
        
        # 檢查評分者和被評者是否相同
        if data['evaluator_id'] == data['target_id']:
            return jsonify({'success': False, 'message': '評分者和被評者不能是同一人'})
        
        # 檢查評分者和被評者是否存在
        evaluator = User.query.get(data['evaluator_id'])
        target = User.query.get(data['target_id'])
        
        if not evaluator or not target:
            return jsonify({'success': False, 'message': '找不到指定的使用者'})
        
        # 檢查是否已存在相同的問卷任務
        existing_feedback = Feedback.query.filter_by(
            evaluator_id=data['evaluator_id'],
            target_id=data['target_id'],
            status='pending'
        ).first()
        
        if existing_feedback:
            return jsonify({'success': False, 'message': '已存在相同的問卷任務'})
        
        # 建立新的問卷任務
        feedback = Feedback(
            evaluator_id=data['evaluator_id'],
            target_id=data['target_id'],
            status='pending'
        )
        
        db.session.add(feedback)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '問卷任務建立成功',
            'feedback_id': feedback.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'建立問卷任務時發生錯誤：{str(e)}'})

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

@app.route('/admin/users/download_template')
@login_required
@admin_required
def download_user_template():
    # 建立一個新的 Excel 檔案
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet('使用者範本')
    
    # 設定欄位標題
    headers = ['使用者名稱', '姓名', '電子郵件', '密碼', '部門', '管理員權限']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)
    
    # 設定欄位格式
    worksheet.set_column('A:F', 20)
    
    # 關閉工作簿
    workbook.close()
    
    # 準備下載
    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='user_template.xlsx'
    )

@app.route('/admin/users/upload', methods=['POST'])
@login_required
@admin_required
def upload_users():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '沒有上傳檔案'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '沒有選擇檔案'})
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': '只接受 Excel 檔案'})
    
    try:
        # 讀取 Excel 檔案
        df = pd.read_excel(file)
        print(f"成功讀取 Excel 檔案，共 {len(df)} 筆資料")  # 除錯用
        
        # 檢查必要欄位
        required_columns = ['使用者名稱', '姓名', '電子郵件', '密碼', '部門', '管理員權限']
        if not all(col in df.columns for col in required_columns):
            missing_columns = [col for col in required_columns if col not in df.columns]
            return jsonify({'success': False, 'message': f'缺少必要欄位：{", ".join(missing_columns)}'})
        
        # 處理每一行資料
        success_count = 0
        error_messages = []
        
        for index, row in df.iterrows():
            try:
                print(f"處理第 {index+2} 行資料")  # 除錯用
                
                # 轉換資料類型
                username = str(row['使用者名稱']).strip()
                full_name = str(row['姓名']).strip()
                email = str(row['電子郵件']).strip()
                password = str(row['密碼']).strip()
                department_name = str(row['部門']).strip()
                is_admin = str(row['管理員權限']).strip().lower() == '是'
                
                # 檢查使用者名稱是否已存在
                if User.query.filter_by(username=username).first():
                    error_messages.append(f'第 {index+2} 行：使用者名稱已存在')
                    continue
                
                # 檢查電子郵件是否已存在
                if User.query.filter_by(email=email).first():
                    error_messages.append(f'第 {index+2} 行：電子郵件已存在')
                    continue
                
                # 取得部門
                department = Department.query.filter_by(name=department_name).first()
                if not department:
                    error_messages.append(f'第 {index+2} 行：部門不存在')
                    continue
                
                # 建立新使用者
                user = User(
                    username=username,
                    full_name=full_name,
                    email=email,
                    department_id=department.id,
                    is_admin=is_admin,
                    is_active=True
                )
                user.set_password(password)
                db.session.add(user)
                print(f"成功建立使用者：{user.username}")  # 除錯用
                success_count += 1
                
            except Exception as e:
                error_messages.append(f'第 {index+2} 行：{str(e)}')
                print(f"處理第 {index+2} 行時發生錯誤：{str(e)}")  # 除錯用
        
        # 提交所有變更到資料庫
        try:
            db.session.commit()
            print("成功提交資料庫變更")  # 除錯用
        except Exception as e:
            db.session.rollback()
            print(f"提交資料庫變更時發生錯誤：{str(e)}")  # 除錯用
            return jsonify({'success': False, 'message': f'提交資料庫變更時發生錯誤：{str(e)}'})
        
        # 回傳結果
        message = f'成功新增 {success_count} 位使用者'
        if error_messages:
            message += f'，但有 {len(error_messages)} 筆資料處理失敗：\n' + '\n'.join(error_messages)
        
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        db.session.rollback()
        print(f"處理檔案時發生錯誤：{str(e)}")  # 除錯用
        return jsonify({'success': False, 'message': f'處理檔案時發生錯誤：{str(e)}'})

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

@app.route('/admin/goals/create', methods=['POST'])
@login_required
@admin_required
def create_goal():
    try:
        # 從表單獲取數據
        name = request.form.get('name')
        description = request.form.get('description')
        owner_id = request.form.get('owner_id')
        department_id = request.form.get('department_id')
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d').date()
        progress = request.form.get('progress', type=int)
        
        # 創建新目標
        goal = PerformanceGoal(
            name=name,
            description=description,
            owner_id=owner_id,
            department_id=department_id,
            start_date=start_date,
            end_date=end_date,
            progress=progress,
            status='進行中'
        )
        
        db.session.add(goal)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/goals/<int:goal_id>', methods=['GET'])
@login_required
@admin_required
def get_goal(goal_id):
    goal = PerformanceGoal.query.get_or_404(goal_id)
    return jsonify({
        'id': goal.id,
        'name': goal.name,
        'description': goal.description,
        'owner_id': goal.owner_id,
        'department_id': goal.department_id,
        'start_date': goal.start_date.strftime('%Y-%m-%d'),
        'end_date': goal.end_date.strftime('%Y-%m-%d'),
        'progress': goal.progress,
        'status': goal.status
    })

@app.route('/admin/goals/<int:goal_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_goal(goal_id):
    try:
        goal = PerformanceGoal.query.get_or_404(goal_id)
        
        # 更新目標數據
        goal.name = request.form.get('name', goal.name)
        goal.description = request.form.get('description', goal.description)
        goal.owner_id = request.form.get('owner_id', goal.owner_id)
        goal.department_id = request.form.get('department_id', goal.department_id)
        
        if request.form.get('start_date'):
            goal.start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d').date()
        if request.form.get('end_date'):
            goal.end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d').date()
            
        goal.progress = request.form.get('progress', goal.progress, type=int)
        
        # 根據進度更新狀態
        if goal.progress == 100:
            goal.status = '已完成'
        elif goal.end_date < datetime.now().date():
            goal.status = '已逾期'
        else:
            goal.status = '進行中'
            
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/goals/<int:goal_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_goal(goal_id):
    try:
        goal = PerformanceGoal.query.get_or_404(goal_id)
        db.session.delete(goal)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# 獲取任務資料
@app.route('/admin/feedback/<int:task_id>', methods=['GET'])
@login_required
@admin_required
def get_feedback_task(task_id):
    try:
        task = Feedback.query.get_or_404(task_id)
        return jsonify({
            'success': True,
            'task': {
                'id': task.id,
                'title': task.title,
                'target_id': task.target_id,
                'evaluator_id': task.evaluator_id,
                'start_date': task.start_date.strftime('%Y-%m-%d'),
                'end_date': task.end_date.strftime('%Y-%m-%d'),
                'description': task.description
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# 刪除任務
@app.route('/admin/feedback/<int:task_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_feedback_task(task_id):
    try:
        task = Feedback.query.get_or_404(task_id)
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True, 'message': '任務已成功刪除'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'刪除失敗：{str(e)}'})

if __name__ == '__main__':
    with app.app_context():
        # 先建立所有資料表
        db.create_all()
        
        # 檢查是否需要建立預設資料
        if not Department.query.first():
            # 建立預設管理員帳號
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    is_admin=True,
                    full_name='Administrator',
                    email='admin@example.com',
                    employee_id='EMP000',
                    position='系統管理員',
                    is_active=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                
            # 建立 David 的管理者帳號
            david = User.query.filter_by(username='David').first()
            if not david:
                david = User(
                    username='David',
                    is_admin=True,
                    full_name='David',
                    email='david@example.com',
                    employee_id='EMP001',
                    position='系統管理員',
                    is_active=True
                )
                david.set_password('123456')
                db.session.add(david)
                db.session.commit()
            
            # 建立預設部門
            departments = [
                Department(name='管理部'),
                Department(name='研發部'),
                Department(name='業務部'),
                Department(name='行銷部'),
                Department(name='財務部')
            ]
            db.session.add_all(departments)
        db.session.commit()
    
    app.run(debug=True) 