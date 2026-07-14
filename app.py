from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv('SECRET_KEY')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

if not SECRET_KEY:
    raise RuntimeError('SECRET_KEY environment variable is not set.')
if not ADMIN_PASSWORD:
    raise RuntimeError('ADMIN_PASSWORD environment variable is not set.')

app.secret_key = SECRET_KEY

# Storage setup - can easily be directed to a persistent disk mount path like '/data/malika.db'
DB_FILE = 'malika.db'
UPLOAD_FOLDER = 'static/images/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

HARDCODED_PRODUCTS = [
    (-1, 'Sample Phone Case', 500.0, 'Durable silicone case, various colors.', None, 'Accessories'),
    (-2, 'Sample Charger Cable', 300.0, 'Fast-charging USB-C cable, 1m.', None, 'Accessories'),
    (-3, 'Sample Screen Protector', 250.0, 'Tempered glass, scratch resistant.', None, 'Accessories'),
]


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    """Return a new SQLite connection that allows row indexing and key lookups."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            image TEXT,
            category TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            product_name TEXT,
            price REAL,
            quantity INTEGER,
            FOREIGN KEY(order_id) REFERENCES orders(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0,
            lockout_until TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    c.close()
    conn.close()


init_db()


def check_login_attempts(ip):
    now = datetime.now(timezone.utc)
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT attempts, lockout_until FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    c.close()
    conn.close()
    if row:
        attempts, lockout_until_str = row['attempts'], row['lockout_until']
        if lockout_until_str:
            # Parse text back into timezone-aware object
            lockout_until = datetime.fromisoformat(lockout_until_str)
            if now < lockout_until:
                remaining = int((lockout_until - now).seconds / 60)
                return False, remaining
    return True, 0


def record_failed_attempt(ip):
    now = datetime.now(timezone.utc)
    lockout_until = None
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT attempts FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    attempts = (row['attempts'] + 1) if row else 1
    if attempts >= 5:
        lockout_until = (now + timedelta(hours=6)).isoformat()
    if row:
        c.execute('UPDATE login_attempts SET attempts=?, lockout_until=? WHERE ip=?',
                  (attempts, lockout_until, ip))
    else:
        c.execute('INSERT INTO login_attempts (ip, attempts, lockout_until) VALUES (?, ?, ?)',
                  (ip, attempts, lockout_until))
    conn.commit()
    c.close()
    conn.close()


def reset_attempts(ip):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM login_attempts WHERE ip = ?', (ip,))
    conn.commit()
    c.close()
    conn.close()


def login_attempts_count(ip):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT attempts FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    c.close()
    conn.close()
    return row['attempts'] if row else 0


def get_products(query='', category=''):
    conn = get_db()
    c = conn.cursor()
    if query:
        c.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
                  (f'%{query}%', f'%{query}%'))
    elif category:
        c.execute("SELECT * FROM products WHERE category = ?", (category,))
    else:
        c.execute("SELECT * FROM products")
    all_products = c.fetchall()
    
    c.execute("SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''")
    categories = [row['category'] for row in c.fetchall()]
    c.close()
    conn.close()

    if not all_products and not query and not category:
        all_products = HARDCODED_PRODUCTS
        categories = sorted({p[5] for p in HARDCODED_PRODUCTS})

    return all_products, categories


@app.route('/')
def home():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    all_products, categories = get_products(query, category)
    return render_template('products.html', products=all_products,
                           categories=categories, query=query,
                           active_category=category)


@app.route('/products')
def products():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    all_products, categories = get_products(query, category)
    return render_template('products.html', products=all_products,
                           categories=categories, query=query,
                           active_category=category)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed = generate_password_hash(password)
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                      (name, email, hashed))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.rollback()
            return render_template('register.html', error='Email already registered')
        finally:
            c.close()
            conn.close()
    return render_template('register.html')
