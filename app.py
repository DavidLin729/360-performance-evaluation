from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import csv
import io
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///performance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 用戶模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

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
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('您沒有管理者權限')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    pending_feedbacks = Feedback.query.filter_by(evaluator_id=user.id, status='pending').all()
    completed_feedbacks = Feedback.query.filter_by(evaluator_id=user.id, status='completed').all()
    return render_template('index.html', 
                         pending_feedbacks=pending_feedbacks, 
                         completed_feedbacks=completed_feedbacks,
                         User=User)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        flash('帳號或密碼錯誤')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
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
    users = User.query.all()
    feedbacks = Feedback.query.all()
    return render_template('admin/dashboard.html', users=users, feedbacks=feedbacks, User=User)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # 創建管理員帳號
        if not User.query.filter_by(username='David').first():
            admin = User(
                username='David',
                password=generate_password_hash('12345678'),
                is_admin=True
            )
            db.session.add(admin)
        
        # 創建測試用戶
        test_users = ['user1', 'user2', 'user3', 'user4']
        for username in test_users:
            if not User.query.filter_by(username=username).first():
                user = User(
                    username=username,
                    password=generate_password_hash('12345678'),
                    is_admin=False
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