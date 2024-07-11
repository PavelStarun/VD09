from app import app, db
from app.models import User, GameResult

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создание всех таблиц
    app.run(debug=True)
