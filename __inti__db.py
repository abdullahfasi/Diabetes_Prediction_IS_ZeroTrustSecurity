from app import create_app, bcrypt
from app.models import db, User

app = create_app()

def initialize_database():
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Check if admin user already exists
        if not User.query.filter_by(username='admin').first():
            # Add a test user
            test_user = User(
                username='admin',
                password=bcrypt.generate_password_hash('admin123').decode('utf-8')
            )
            db.session.add(test_user)
            db.session.commit()
            print("Database initialized with test user (admin:admin123)")
        else:
            print("Admin user already exists")

if __name__ == '__main__':
    initialize_database()