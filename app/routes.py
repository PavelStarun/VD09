from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm
from app.models import User, GameResult


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('Пользователь с таким именем уже существует.', 'danger')
        elif form.password.data != form.confirm_password.data:
            flash('Пароли не совпадают.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Ваш аккаунт создан!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Вход не выполнен. Неправильное имя пользователя или пароль.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/submit_score', methods=['POST'])
@login_required
def submit_score():
    data = request.get_json()
    clicks = data.get('clicks')
    duration = data.get('duration')

    new_result = GameResult(user_id=current_user.id, duration=duration, clicks=clicks)
    db.session.add(new_result)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/leaderboard/<int:duration>')
def leaderboard(duration):
    users = User.query.all()
    results = {}
    for user in users:
        user_results = GameResult.query.filter_by(user_id=user.id, duration=duration).order_by(
            GameResult.clicks.desc()).all()
        if user_results:
            best_result = user_results[0].clicks
            last_five_results = [result.clicks for result in user_results[:5]]
            results[user.username] = {'best_result': best_result, 'last_five_results': last_five_results}
    sorted_results = dict(sorted(results.items(), key=lambda item: item[1]['best_result'], reverse=True))
    return render_template('leaderboard.html', results=sorted_results, duration=duration)
