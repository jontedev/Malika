from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

UPLOAD_FOLDER = 'static/images/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '22@2005')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    conn = sqlite3.connect('malika.db')
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            FOREIGN KEY (order_id) REFERENCES orders(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0,
            lockout_until TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def check_login_attempts(ip):
    now = datetime.now()
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('SELECT attempts, lockout_until FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    conn.close()
    if row:
        attempts, lockout_until = row
        if lockout_until:
            try:
                lockout_time = datetime.strptime(lockout_until, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                lockout_time = datetime.strptime(lockout_until, '%Y-%m-%d %H:%M:%S')
            if now < lockout_time:
                remaining = int((lockout_time - now).seconds / 60)
                return False, remaining
    return True, 0

def record_failed_attempt(ip):
    now = datetime.now()
    lockout_until = None
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('SELECT attempts FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    attempts = (row[0] + 1) if row else 1
    if attempts >= 5:
        lockout_until = now + timedelta(hours=6)
    if row:
        c.execute('UPDATE login_attempts SET attempts=?, lockout_until=? WHERE ip=?',
                  (attempts, lockout_until, ip))
    else:
        c.execute('INSERT INTO login_attempts (ip, attempts, lockout_until) VALUES (?, ?, ?)',
                  (ip, attempts, lockout_until))
    conn.commit()
    conn.close()

def reset_attempts(ip):
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('DELETE FROM login_attempts WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

def login_attempts_count(ip):
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('SELECT attempts FROM login_attempts WHERE ip = ?', (ip,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0

def get_products(query='', category=''):
    conn = sqlite3.connect('malika.db')
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
    categories = [row[0] for row in c.fetchall()]
    conn.close()
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
        try:
            conn = sqlite3.connect('malika.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                      (name, email, hashed))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Email already registered')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('malika.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[3], password):
            session['user'] = {'id': user[0], 'name': user[1], 'email': user[2]}
            return redirect(url_for('home'))
        return render_template('login.html', error='Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/mk-dashboard/login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr
    allowed, remaining = check_login_attempts(ip)
    if not allowed:
        return render_template('admin_login.html',
                             error=f'Too many attempts. Try again in {remaining} minutes.')
    if request.method == 'POST':
        password = request.form['password']
        if password == ADMIN_PASSWORD:
            reset_attempts(ip)
            session['admin'] = True
            return redirect(url_for('admin'))
        else:
            record_failed_attempt(ip)
            allowed, remaining = check_login_attempts(ip)
            if not allowed:
                return render_template('admin_login.html',
                                     error='Too many attempts. Locked for 6 hours.')
            attempts_left = 5 - login_attempts_count(ip)
            return render_template('admin_login.html',
                                 error=f'Wrong password. {attempts_left} attempts remaining.')
    return render_template('admin_login.html')

@app.route('/mk-dashboard/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/mk-dashboard')
def admin():
    if not session.get('admin'):
        return redirect(url_for('home'))
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products')
    products = c.fetchall()
    c.execute('SELECT * FROM orders ORDER BY created_at DESC')
    orders = c.fetchall()
    conn.close()
    return render_template('admin.html', products=products, orders=orders)

@app.route('/mk-dashboard/add', methods=['POST'])
def add_product():
    if not session.get('admin'):
        return redirect(url_for('home'))
    name = request.form['name']
    price = request.form['price']
    description = request.form['description']
    category = request.form['category']
    image = request.files.get('image')
    image_filename = None
    if image and image.filename != '' and allowed_file(image.filename):
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('INSERT INTO products (name, price, description, image, category) VALUES (?, ?, ?, ?, ?)',
              (name, price, description, image_filename, category))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

@app.route('/mk-dashboard/edit/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    if not session.get('admin'):
        return redirect(url_for('home'))
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']
        category = request.form['category']
        image = request.files.get('image')
        if image and image.filename != '' and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            c.execute('UPDATE products SET name=?, price=?, description=?, image=?, category=? WHERE id=?',
                      (name, price, description, image_filename, category, id))
        else:
            c.execute('UPDATE products SET name=?, price=?, description=?, category=? WHERE id=?',
                      (name, price, description, category, id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin'))
    c.execute('SELECT * FROM products WHERE id = ?', (id,))
    product = c.fetchone()
    conn.close()
    return render_template('edit_product.html', product=product)

@app.route('/mk-dashboard/delete/<int:id>')
def delete_product(id):
    if not session.get('admin'):
        return redirect(url_for('home'))
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('DELETE FROM products WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

@app.route('/cart')
def cart():
    cart_items = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/cart/add/<int:id>')
def add_to_cart(id):
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products WHERE id = ?', (id,))
    product = c.fetchone()
    conn.close()
    if not product:
        return redirect(url_for('home'))
    cart = session.get('cart', [])
    for item in cart:
        if item['id'] == id:
            item['quantity'] += 1
            session['cart'] = cart
            return redirect(url_for('home'))
    cart.append({
        'id': product[0],
        'name': product[1],
        'price': product[2],
        'image': product[4],
        'quantity': 1
    })
    session['cart'] = cart
    return redirect(url_for('home'))

@app.route('/cart/remove/<int:id>')
def remove_from_cart(id):
    cart = session.get('cart', [])
    cart = [item for item in cart if item['id'] != id]
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    cart_items = session.get('cart', [])
    if not cart_items:
        return redirect(url_for('cart'))
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        conn = sqlite3.connect('malika.db')
        c = conn.cursor()
        c.execute('INSERT INTO orders (name, phone, address, total) VALUES (?, ?, ?, ?)',
                  (name, phone, address, total))
        order_id = c.lastrowid
        for item in cart_items:
            c.execute('INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES (?, ?, ?, ?, ?)',
                      (order_id, item['id'], item['name'], item['price'], item['quantity']))
        conn.commit()
        conn.close()
        session.pop('cart', None)
        return redirect(url_for('order_success', order_id=order_id))
    return render_template('checkout.html', cart_items=cart_items, total=total)

@app.route('/order/success/<int:order_id>')
def order_success(order_id):
    return render_template('order_success.html', order_id=order_id)

@app.route('/mk-dashboard/order/status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if not session.get('admin'):
        return redirect(url_for('home'))
    status = request.form['status']
    conn = sqlite3.connect('malika.db')
    c = conn.cursor()
    c.execute('UPDATE orders SET status=? WHERE id=?', (status, order_id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
