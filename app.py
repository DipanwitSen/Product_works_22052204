import os
import sqlite3
import smtplib
import razorpay
import requests
import secrets
import json
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email.mime.text import MIMEText

# Flask Config
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret-localmart-key")

UPLOAD_FOLDER = 'static/images/products'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Razorpay Config
RAZORPAY_KEY = os.getenv("RAZORPAY_KEY", "rzp_test_RJbeRtchCzjRnl")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET", "U1n6sacDbHO3CDCUstNBCs4C")
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))

# Groq LLM Config - REMOVED

# Database Setup
DATABASE = 'localmart.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                seller_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                image_url TEXT,
                variant TEXT,
                stock INTEGER NOT NULL,
                specifications TEXT,
                manufacturing_area TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES users(id)
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cart (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                variant TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wishlist (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id),
                UNIQUE(user_id, product_id)
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                razorpay_order_id TEXT UNIQUE NOT NULL,
                total_amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending Payment',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                quantity INTEGER NOT NULL,
                variant TEXT,
                image_url TEXT,
                FOREIGN KEY (order_id) REFERENCES orders(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            );
        ''')

        db.commit()

init_db()

# Helper Functions

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in to access this page.", 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def seller_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'seller':
            flash("You do not have permission to access this page.", 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_cart_items(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT 
            c.id as cart_id, 
            c.product_id as id, 
            c.quantity, 
            c.variant,
            p.name, 
            p.price, 
            p.image_url
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?;
    ''', (user_id,))
    return cursor.fetchall()

def delete_file_if_exists(filename):
    """Deletes a file from the UPLOAD_FOLDER if it exists."""
    if filename and filename != 'default.jpg': # Prevent deleting a default placeholder image
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted file: {file_path}")

# Routes: Authentication

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", 'error')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')
        
        db = get_db()
        cursor = db.cursor()
        
        try:
            password_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, role)
            )
            db.commit()
            flash("Account created successfully! Please log in.", 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", 'error')
            
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", 'success')
    return redirect(url_for('index'))

# Routes: Products

@app.route('/')
def index():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()

    products = [dict(row) for row in products]

    return render_template('home.html', products=products)


@app.route('/product/<int:product_id>')
def product_details(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash("Product not found.", 'error')
        return redirect(url_for('index'))
    
    product_dict = dict(product)
    product_dict['variants'] = [v.strip() for v in product_dict['variant'].split(',') if v.strip()] if product_dict['variant'] else []
    
    return render_template('product_details.html', product=product_dict)


# app.py - Routes: Products (start replacement here)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@seller_required
def add_product():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        price_str = request.form.get('price', '0').strip()
        variant = request.form.get('variant', '').strip()
        stock_str = request.form.get('stock', '0').strip()
        specifications = request.form.get('specifications', '').strip()
        manufacturing_area = request.form.get('manufacturing_area', '').strip()
        description = request.form.get('description', '').strip()
        image_file = request.files.get('image_file')

        try:
            price = float(price_str)
            stock = int(stock_str)
        except ValueError:
            flash("Invalid price or stock value.", 'error')
            return render_template('add_product.html')

        image_url = save_image(image_file)
        if not image_url:
            flash("Product image is required or the file type is invalid (use png, jpg, jpeg, gif).", 'error')
            return render_template('add_product.html')

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO products (seller_id, name, description, price, image_url, variant, stock, specifications, manufacturing_area)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], name, description, price, image_url, variant, stock, specifications, manufacturing_area))
        db.commit()

        flash(f"Product '{name}' added successfully!", 'success')
        return redirect(url_for('index'))
    
    return render_template('add_product.html')


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@seller_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 1. Fetch product and check existence
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash("Product not found.", 'error')
        return redirect(url_for('index'))
    
    product_dict = dict(product) # Convert to dictionary for easier template usage
    
    # 2. Check ownership
    if product_dict['seller_id'] != session.get('user_id'):
        flash("You can only edit products you have listed.", 'error')
        return redirect(url_for('product_details', product_id=product_id))

    if request.method == 'POST':
        # Get data from form
        name = request.form.get('name', '').strip()
        price_str = request.form.get('price', '0').strip()
        variant = request.form.get('variant', '').strip()
        stock_str = request.form.get('stock', '0').strip()
        specifications = request.form.get('specifications', '').strip()
        manufacturing_area = request.form.get('manufacturing_area', '').strip()
        description = request.form.get('description', '').strip()
        image_file = request.files.get('image_file')

        try:
            price = float(price_str)
            stock = int(stock_str)
        except ValueError:
            flash("Invalid price or stock value.", 'error')
            # Pass back product_dict to re-populate the form
            return render_template('add_product.html', product=product_dict)

        # Handle image upload
        image_url = product_dict['image_url']
        if image_file and image_file.filename != '':
            new_image_url = save_image(image_file)
            if new_image_url:
                # OPTIONAL: Delete old image file from UPLOAD_FOLDER
                if image_url:
                    old_filename = os.path.basename(image_url)
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], old_filename)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                image_url = new_image_url
            else:
                flash("Invalid image file type. Supported types: png, jpg, jpeg, gif.", 'error')
                return render_template('add_product.html', product=product_dict)

        # Update product in DB
        cursor.execute('''
            UPDATE products 
            SET name = ?, description = ?, price = ?, image_url = ?, variant = ?, stock = ?, specifications = ?, manufacturing_area = ?
            WHERE id = ?
        ''', (name, description, price, image_url, variant, stock, specifications, manufacturing_area, product_id))
        db.commit()

        flash("Product updated successfully!", 'success')
        return redirect(url_for('product_details', product_id=product_id))

    # GET request: Show edit form
    return render_template('add_product.html', product=product_dict)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
@seller_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 1. Fetch product and check existence
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash("Product not found.", 'error')
        return redirect(url_for('index'))
    
    product_dict = dict(product)
    
    # 2. Check ownership
    if product_dict['seller_id'] != session.get('user_id'):
        flash("You can only delete products you have listed.", 'error')
        return redirect(url_for('product_details', product_id=product_id))

    # 3. Delete image file from server
    if product_dict['image_url']:
        try:
            filename = os.path.basename(product_dict['image_url'])
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"Error deleting image file {filename}: {e}")

    # 4. Delete product from DB
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    
    flash(f"Product '{product_dict['name']}' has been deleted successfully.", 'success')
    return redirect(url_for('index'))

# Routes: Cart & Wishlist

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    conn = get_db_connection()
    try:
        product = conn.execute("SELECT stock, name FROM products WHERE id = ?", (product_id,)).fetchone()
        if not product or product['stock'] < quantity:
            flash(f"Failed to add to cart: Not enough stock for {product['name']}.", 'danger')
            return redirect(url_for('product_details', product_id=product_id))

        existing_item = conn.execute(
            "SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?",
            (session['user_id'], product_id)
        ).fetchone()

        if existing_item:
            new_quantity = existing_item['quantity'] + quantity
            if new_quantity > product['stock']:
                flash(f"Cannot add more. Total requested quantity ({new_quantity}) exceeds available stock ({product['stock']}).", 'warning')
                return redirect(url_for('product_details', product_id=product_id))

            conn.execute(
                "UPDATE cart SET quantity = ? WHERE id = ?",
                (new_quantity, existing_item['id'])
            )
        else:
            conn.execute(
                "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
                (session['user_id'], product_id, quantity)
            )
        conn.commit()
        flash(f'Added {quantity}x {product["name"]} to cart!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    conn = get_db_connection()
    cart_items = conn.execute(
        """
        SELECT c.id AS cart_id, p.id, p.name, p.price, c.quantity, p.image_url, p.stock
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
        """,
        (session['user_id'],)
    ).fetchall()

    total = sum(item['price'] * item['quantity'] for item in cart_items)
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/remove_from_cart/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', (cart_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Item removed from cart.', 'info')
    return redirect(url_for('cart'))

@app.route('/increase_quantity/<int:cart_id>')
@login_required
def increase_quantity(cart_id):
    conn = get_db_connection()
    try:
        item = conn.execute(
            """
            SELECT c.quantity, p.stock, p.name, p.id
            FROM cart c JOIN products p ON c.product_id = p.id
            WHERE c.id = ? AND c.user_id = ?
            """,
            (cart_id, session['user_id'])
        ).fetchone()

        if item:
            new_quantity = item['quantity'] + 1
            if new_quantity <= item['stock']:
                conn.execute('UPDATE cart SET quantity = ? WHERE id = ?', (new_quantity, cart_id))
                conn.commit()
                flash(f'Increased quantity of {item["name"]}.', 'success')
            else:
                flash(f'Cannot increase quantity. Max stock for {item["name"]} reached ({item["stock"]}).', 'warning')
        else:
            flash('Cart item not found.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('cart'))

@app.route('/decrease_quantity/<int:cart_id>')
@login_required
def decrease_quantity(cart_id):
    conn = get_db_connection()
    try:
        query = """
        SELECT c.quantity, p.name 
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.id = ? AND c.user_id = ?
        """
        item = conn.execute(query, (cart_id, session['user_id'])).fetchone()

        if item:
            product_name = item['name']
            new_quantity = item['quantity'] - 1
            
            if new_quantity >= 1:
                conn.execute(
                    'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?', 
                    (new_quantity, cart_id, session['user_id'])
                )
                flash(f'Decreased quantity of {product_name}.', 'success')
            else:
                # 3. Delete the item from the cart table
                conn.execute(
                    'DELETE FROM cart WHERE id = ? AND user_id = ?', 
                    (cart_id, session['user_id'])
                )
                flash(f'Removed {product_name} from cart.', 'info')
                
            conn.commit()
        else:
            flash('Cart item not found or does not belong to your account.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {e}', 'danger') 
    finally:
        conn.close()
    return redirect(url_for('cart'))


@app.route('/wishlist')
@login_required
def wishlist():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT 
            w.id as wishlist_id, 
            p.id, 
            p.name, 
            p.price, 
            p.image_url, 
            p.variant
        FROM wishlist w
        JOIN products p ON w.product_id = p.id
        WHERE w.user_id = ?;
    ''', (session['user_id'],))
    items = cursor.fetchall()
    return render_template('wishlist.html', items=items)

@app.route('/add_to_wishlist/<int:product_id>')
@login_required
def add_to_wishlist(product_id):
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    try:
        cursor.execute('''
            INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)
        ''', (user_id, product_id))
        db.commit()
        flash("Product added to wishlist.", 'success')
    except sqlite3.IntegrityError:
        flash("Product is already in your wishlist.", 'info')
        
    return redirect(url_for('product_details', product_id=product_id))

@app.route('/remove_from_wishlist/<int:wishlist_id>')
@login_required
def remove_from_wishlist(wishlist_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM wishlist WHERE id = ? AND user_id = ?", (wishlist_id, session['user_id']))
    db.commit()
    flash("Item removed from wishlist.", 'info')
    return redirect(url_for('wishlist'))

# Routes: Razorpay Checkout & Orders
@app.route('/checkout_selection', methods=['POST'])
@login_required
def checkout_selection():
    selected_cart_ids = request.form.getlist('selected_items')

    if not selected_cart_ids:
        flash('Please select at least one item to proceed to checkout.', 'warning')
        return redirect(url_for('cart'))
    session['checkout_cart_ids'] = selected_cart_ids

    return redirect(url_for('checkout'))


@app.route('/checkout')
@login_required
def checkout():
    # Placeholder for a proper checkout rendering, using session data
    selected_cart_ids = session.get('checkout_cart_ids', [])
    if not selected_cart_ids:
        flash("No items selected for checkout. Please select items in your cart.", 'error')
        return redirect(url_for('cart'))
    
    db = get_db()
    user_id = session['user_id']
    placeholders = ','.join('?' for _ in selected_cart_ids)
    
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT 
            c.id as cart_id, 
            c.product_id, 
            c.quantity, 
            c.variant,
            p.name, 
            p.price, 
            p.image_url
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ? AND c.id IN ({placeholders});
    ''', (user_id, *selected_cart_ids))
    cart_items = cursor.fetchall()
    
    if not cart_items:
        flash("Selected cart items not found or cart is empty.", 'error')
        return redirect(url_for('cart'))

    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

    return render_template('checkout.html', cart_items=cart_items, total=total_amount, razorpay_key=RAZORPAY_KEY)

@app.route('/create_order', methods=['POST'])
@login_required
def create_order():
    db = get_db()
    user_id = session['user_id']
    
    selected_cart_ids = session.get('checkout_cart_ids', [])
    if not selected_cart_ids:
        return jsonify({"error": "No items selected"}), 400

    placeholders = ','.join('?' for _ in selected_cart_ids)
    
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT 
            c.id as cart_id, 
            c.product_id, 
            c.quantity, 
            c.variant,
            p.name, 
            p.price, 
            p.image_url
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ? AND c.id IN ({placeholders});
    ''', (user_id, *selected_cart_ids))
    cart_items = cursor.fetchall()
    
    if not cart_items:
        return jsonify({"error": "Selected cart items not found or cart is empty"}), 404

    total_amount_paise = int(sum(item['price'] * item['quantity'] * 100 for item in cart_items))
    
    if total_amount_paise == 0:
         return jsonify({"error": "Total amount is zero"}), 400

    try:
        razorpay_order = razorpay_client.order.create({
            'amount': total_amount_paise,
            'currency': 'INR',
            'receipt': f'order_rcptid_{user_id}_{secrets.token_hex(4)}',
            'payment_capture': '1'
        })
        razorpay_order_id = razorpay_order['id']

        cursor.execute('''
            INSERT INTO orders (user_id, razorpay_order_id, total_amount, status)
            VALUES (?, ?, ?, 'Pending Payment')
        ''', (user_id, razorpay_order_id, total_amount_paise / 100))
        order_id = cursor.lastrowid
        
        for item in cart_items:
            cursor.execute('''
                INSERT INTO order_items (order_id, product_id, name, price, quantity, variant, image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (order_id, item['product_id'], item['name'], item['price'], item['quantity'], item['variant'], item['image_url']))
            
        db.commit()

        return jsonify({
            "order_id": razorpay_order_id,
            "amount": total_amount_paise,
            "currency": "INR",
            "name": session.get('username', 'LocalMart Customer'),
            "email": "user@example.com",
            "contact": "9876543210"
        })

    except Exception as e:
        db.rollback()
        print(f"Razorpay Order Creation Error: {e}")
        return jsonify({"error": f"Failed to create Razorpay order: {e}"}), 500


@app.route('/payment_success', methods=['POST'])
@login_required
def payment_success():
    db = get_db()
    user_id = session['user_id']
    data = request.json
    
    razorpay_order_id = data.get('razorpay_order_id')
    razorpay_payment_id = data.get('razorpay_payment_id')
    razorpay_signature = data.get('razorpay_signature')
    
    if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
        return jsonify({"status": "error", "message": "Missing payment data."}), 400

    try:
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        
        razorpay_client.utility.verify_payment_signature(params_dict)

        cursor = db.cursor()
        cursor.execute('''
            UPDATE orders 
            SET status = 'Paid' 
            WHERE razorpay_order_id = ? AND user_id = ? AND status = 'Pending Payment'
        ''', (razorpay_order_id, user_id))
        
        if cursor.rowcount == 0:
            db.rollback()
            return jsonify({"status": "error", "message": "Order not found or already processed."}), 404
            
        selected_cart_ids = session.pop('checkout_cart_ids', [])
        if selected_cart_ids:
            placeholders = ','.join('?' for _ in selected_cart_ids)
            cursor.execute(f"DELETE FROM cart WHERE user_id = ? AND id IN ({placeholders})", 
                           (user_id, *selected_cart_ids))

        db.commit()
        
        flash("Payment successful! Your order has been placed.", 'success')
        return jsonify({"status": "success", "order_id": razorpay_order_id})

    except Exception as e:
        db.rollback()
        print(f"Payment Verification Error: {e}")
        flash("Payment verification failed. Please contact support with your payment ID.", 'error')
        return jsonify({"status": "failure", "message": f"Payment verification failed: {e}"}), 400

@app.route('/orders')
@login_required
def orders():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT 
            oi.order_id as id,
            oi.name,
            oi.product_id,
            oi.price * oi.quantity as amount,
            oi.quantity,
            oi.variant,
            oi.image_url,
            o.created_at,
            o.status
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC;
    ''', (session['user_id'],))
    
    orders = cursor.fetchall()
    return render_template('orders.html', orders=orders)


# Routes: Chatbot API

@app.route("/chat", methods=["POST"])
def chat():
    """Handles user messages and provides chatbot responses with priority on DB search."""
    user_message = request.json.get("message", "").strip()
    db = get_db()
    # Default fallback message
    response_text = "I'm sorry, I don't have an answer for that."
    products = None
    role = session.get('role', 'guest')
    user_id = session.get('user_id')
    try:
        cursor = db.cursor()
        
        # 1. Simple hardcoded responses (Greeting)
        greetings = ["hi", "hello", "hey", "hola", "namaste"]
        if any(g in user_message.lower() for g in greetings):
            return jsonify({"message": "Hello! How can I help you today? You can ask me about our products, or if you're a seller, you can ask about your stock."})

        # 6. Seller-specific commands (only if logged in as a seller)
        if role == 'seller':
            # Seller: Check Stock
            if "check stock" in user_message.lower() or "stock levels" in user_message.lower():
                cursor.execute("SELECT name, stock FROM products WHERE seller_id = ?", (user_id,))
                stock_levels = cursor.fetchall()
                if stock_levels:
                    stock_list = [f"{p['name']}: {p['stock']}" for p in stock_levels]
                    response_text = "Here are your current stock levels:\n" + "\n".join(stock_list)
                else:
                    response_text = "You do not have any products listed yet in your store."
                return jsonify({"message": response_text})
            
            # Seller: Pending Orders
            elif "pending orders" in user_message.lower():
                # Simplified query to show order count
                cursor.execute("""
                    SELECT count(DISTINCT o.id) as order_count FROM orders o 
                    JOIN order_items oi ON o.id = oi.order_id
                    JOIN products p ON oi.product_id = p.id
                    WHERE p.seller_id = ? AND o.status = 'Paid'
                """, (user_id,))
                count = cursor.fetchone()['order_count']
                response_text = f"You have {count} pending orders waiting for fulfillment."
                return jsonify({"message": response_text})
            
            # Seller: Update Price
            elif re.search(r'update price of\s+(.+?)\s+to\s+₹?([\d,]+\.?\d*)', user_message, re.I):
                match = re.search(r'update price of\s+(.+?)\s+to\s+₹?([\d,]+\.?\d*)', user_message, re.I)
                product_name = match.group(1).strip()
                # Clean up price string before conversion
                new_price = float(match.group(2).replace(',', '').strip())
                cursor.execute("UPDATE products SET price = ? WHERE name LIKE ? AND seller_id = ?", (new_price, f"%{product_name}%", user_id))
                db.commit()
                if cursor.rowcount > 0:
                    response_text = f"The price of {product_name.capitalize()} has been updated to ₹{new_price:.2f}."
                else:
                    response_text = f"Could not find product '{product_name.capitalize()}' in your store."
                return jsonify({"message": response_text})
            
            # Seller: Delete Product
            elif re.search(r'delete product\s+(.+)', user_message, re.I):
                product_name = re.search(r'delete product\s+(.+)', user_message, re.I).group(1).strip().replace("from my store", "").strip()
                cursor.execute("DELETE FROM products WHERE name LIKE ? AND seller_id = ?", (f"%{product_name}%", user_id))
                db.commit()
                if cursor.rowcount > 0:
                    response_text = f"The product {product_name.capitalize()} has been deleted."
                else:
                    response_text = f"Could not find product '{product_name.capitalize()}' in your store to delete."
                return jsonify({"message": response_text})
            
        # 7. Order tracking (Buyer)
        if "order" in user_message.lower() and user_id:
            order_match = re.search(r'order\s+#?(\d+)', user_message)
            if order_match:
                order_id = int(order_match.group(1))
                cursor.execute("SELECT status FROM orders WHERE id = ? AND user_id = ?", (order_id, user_id))
                order = cursor.fetchone()
                if order:
                    response_text = f"Order #{order_id} has a status of: {order['status'].capitalize()}"
                else:
                    response_text = "I couldn't find that order. Please make sure the order ID is correct."
            else:
                response_text = "Please provide your order number to check its status. Example: 'Where is my order #12345?'"
            
            return jsonify({"message": response_text})
            
        # 5. Product specifications
        if "specifications" in user_message.lower() and "of" in user_message.lower():
            product_name = user_message.split("of")[-1].strip().replace("?", "")
            cursor.execute("SELECT specifications FROM products WHERE name LIKE ?", (f"%{product_name}%",))
            product_spec = cursor.fetchone()
            if product_spec and product_spec['specifications']:
                response_text = f"The specifications for {product_name.capitalize()} are: {product_spec['specifications']}"
            else:
                response_text = f"I couldn't find specifications for {product_name.capitalize()}."
            
            return jsonify({"message": response_text})
            
        # 2, 3, 4. Product Search (Combined, handles name, max price, min price, range, and EQUAL)
        product_search_match = re.search(r'(?:give me|get me|find|show me|search for|about|product|brand|view|what are|i want|looking for|\w+\s+me|show)\s*(.+)', user_message, re.I)
        
        if product_search_match:
            search_query_raw = product_search_match.group(1).strip().replace("?", "")
            
            # Price Regexes (Updated to handle commas and currency)
            price_range_match = re.search(r'between\s+₹?([\d,]+\.?\d*)\s+and\s+₹?([\d,]+\.?\d*)', search_query_raw, re.I)
            price_min_match = re.search(r'(.+?)\s+(?:above|over|more than)\s+₹?([\d,]+\.?\d*)', search_query_raw, re.I)
            price_max_match = re.search(r'(.+?)\s+(?:under|less than)\s+₹?([\d,]+\.?\d*)', search_query_raw, re.I)
            # NEW: Equal price match regex
            price_equal_match = re.search(r'(.+?)\s+(?:equal|exactly|at)\s+₹?([\d,]+\.?\d*)', search_query_raw, re.I)

            sql_query = "SELECT id, name, price, image_url, description FROM products WHERE (name LIKE ? OR specifications LIKE ? OR variant LIKE ?)"
            params = []
            final_search_term = search_query_raw
            
            if price_range_match: # Price Range
                min_price = float(price_range_match.group(1).replace(',', '').strip())
                max_price = float(price_range_match.group(2).replace(',', '').strip())
                sql_query += " AND price BETWEEN ? AND ? LIMIT 5"
                # Strip price terms for name search
                search_term_for_name = re.sub(r'between\s+₹?[\d,]+\.?\d*\s+and\s+₹?[\d,]+\.?\d*', '', final_search_term, flags=re.I).strip()
                search_term_for_name = f"%{search_term_for_name}%" if search_term_for_name else "%%"
                params.extend([search_term_for_name] * 3)
                params.extend([min_price, max_price])
                response_text = f"Here are products in the range of ₹{min_price:.2f} to ₹{max_price:.2f}:"
                
            elif price_equal_match: # NEW: Exact Price Match
                product_name_for_equal = re.sub(r'(?:equal|exactly|at).*', '', price_equal_match.group(1)).strip()
                price_limit = float(price_equal_match.group(2).replace(',', '').strip())
                
                sql_query += " AND price = ? LIMIT 5"
                final_search_term = product_name_for_equal if product_name_for_equal else search_query_raw.split('equal')[0].split('exactly')[0].split('at')[0].strip()
                
                params.extend([f"%{final_search_term}%"] * 3)
                params.append(price_limit)
                response_text = f"Here's what I found for '{final_search_term.capitalize()}' priced exactly at ₹{price_limit:.2f}:"

            elif price_min_match: # Min Price
                product_name_for_min = re.sub(r'(?:above|over|more than).*', '', price_min_match.group(1)).strip()
                price_limit = float(price_min_match.group(2).replace(',', '').strip())
                
                sql_query += " AND price >= ? LIMIT 5"
                final_search_term = product_name_for_min if product_name_for_min else search_query_raw.split('above')[0].split('over')[0].split('more than')[0].strip()
                
                params.extend([f"%{final_search_term}%"] * 3)
                params.append(price_limit)
                response_text = f"Here's what I found for '{final_search_term.capitalize()}' above ₹{price_limit:.2f}:"

            elif price_max_match: # Max Price
                product_name_for_max = re.sub(r'(?:under|less than).*', '', price_max_match.group(1)).strip()
                price_limit = float(price_max_match.group(2).replace(',', '').strip())
                sql_query += " AND price <= ? LIMIT 5"
                final_search_term = product_name_for_max if product_name_for_max else search_query_raw.split('under')[0].split('less than')[0].strip()
                
                params.extend([f"%{final_search_term}%"] * 3)
                params.append(price_limit)
                response_text = f"Here's what I found for '{final_search_term.capitalize()}' under ₹{price_limit:.2f}:"
            
            else: # General Product Search
                sql_query += " LIMIT 5"
                params.extend([f"%{final_search_term}%"] * 3)
                response_text = f"Here's what I found for '{final_search_term}':"

            products_db = cursor.execute(sql_query, tuple(params)).fetchall()
            
            if products_db:
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image_url": p["image_url"], "description": p["description"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products matching your search criteria: '{search_query_raw}'. I can only help with specific product searches (like 'find shoes' or 'what are the specifications of X'), order tracking, or seller commands."
        
        # Final catch-all for general queries (now fully non-LLM)
        if not products and response_text == "I'm sorry, I don't have an answer for that.":
            response_text = "I'm sorry, I can only help with specific product searches (like 'find shoes' or 'what are the specifications of X'), order tracking, or seller commands."

    except Exception as e:
        print(f"Chatbot error: {e}")
        response_text = "An internal server error occurred while processing your request. Please check the server logs."

    response = {"message": response_text}
    if products:
        response["products"] = [{"id": p.get("id"), "name": p.get("name"), "price": p.get("price"), "image_url": p.get("image_url"), "description": p.get("description", "") } for p in products]
    
    return jsonify(response)
if __name__ == '__main__':
    with app.app_context():
        init_db() 
        
    app.run(debug=True)
