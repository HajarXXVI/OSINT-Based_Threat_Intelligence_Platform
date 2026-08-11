from main import app, db, User

with app.app_context():
    users = User.query.all()
    print("\n--- DATABASE USERS ---")
    for u in users:
        print(f"ID: {u.id} | Username: {u.username} | Password: {u.password} | Role: {u.role} ")
    print("----------------------\n")