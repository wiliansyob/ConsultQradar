from werkzeug.security import generate_password_hash

# Diccionario de usuarios de ejemplo (esto debería ir en una base de datos real)
users = {
    "admin": {"password": generate_password_hash("admin123")},
    "user1": {"password": generate_password_hash("password1")}
    
}