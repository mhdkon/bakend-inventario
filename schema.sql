CREATE TABLE IF NOT EXISTS restaurants (
  id SERIAL PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  plan VARCHAR(20) DEFAULT 'basic',
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER REFERENCES restaurants(id),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(200) NOT NULL,
  role VARCHAR(30) NOT NULL DEFAULT 'admin',
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS categories (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  name VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS suppliers (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  company_name VARCHAR(200) NOT NULL,
  contact_name VARCHAR(200),
  phone VARCHAR(30),
  email VARCHAR(255),
  payment_terms TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  category_id INTEGER REFERENCES categories(id),
  supplier_id INTEGER REFERENCES suppliers(id),
  name VARCHAR(200) NOT NULL,
  sku VARCHAR(100),
  barcode VARCHAR(100),
  description TEXT,
  unit VARCHAR(20) NOT NULL DEFAULT 'ud',
  purchase_price NUMERIC(10,2) NOT NULL DEFAULT 0,
  stock_current NUMERIC(12,3) NOT NULL DEFAULT 0,
  stock_min NUMERIC(12,3) NOT NULL DEFAULT 0,
  location VARCHAR(100),
  image_url TEXT,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS product_batches (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  batch_code VARCHAR(100),
  quantity_received NUMERIC(12,3) NOT NULL,
  quantity_remaining NUMERIC(12,3) NOT NULL,
  unit_cost NUMERIC(10,2),
  expiration_date DATE,
  received_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  batch_id INTEGER REFERENCES product_batches(id),
  user_id INTEGER REFERENCES users(id),
  type VARCHAR(20) NOT NULL,
  quantity NUMERIC(12,3) NOT NULL,
  reason VARCHAR(50) NOT NULL,
  notes TEXT,
  movement_date TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS purchase_orders (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  supplier_id INTEGER NOT NULL REFERENCES suppliers(id),
  user_id INTEGER REFERENCES users(id),
  status VARCHAR(20) DEFAULT 'draft',
  order_date DATE DEFAULT CURRENT_DATE,
  expected_date DATE,
  received_date DATE,
  total_amount NUMERIC(12,2) DEFAULT 0,
  notes TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS purchase_order_items (
  id SERIAL PRIMARY KEY,
  purchase_order_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id),
  quantity NUMERIC(12,3) NOT NULL,
  received_quantity NUMERIC(12,3) DEFAULT 0,
  unit_price NUMERIC(10,2) NOT NULL,
  subtotal NUMERIC(12,2) GENERATED ALWAYS AS (quantity * unit_price) STORED
);

CREATE TABLE IF NOT EXISTS recipes (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  name VARCHAR(200) NOT NULL,
  description TEXT,
  selling_price NUMERIC(10,2) NOT NULL DEFAULT 0,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recipe_ingredients (
  id SERIAL PRIMARY KEY,
  recipe_id INTEGER NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id),
  quantity NUMERIC(12,3) NOT NULL,
  unit VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS sales (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  user_id INTEGER REFERENCES users(id),
  recipe_id INTEGER NOT NULL REFERENCES recipes(id),
  quantity INTEGER NOT NULL DEFAULT 1,
  unit_price NUMERIC(10,2) NOT NULL,
  total NUMERIC(10,2) NOT NULL,
  sale_date TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
  user_id INTEGER REFERENCES users(id),
  action VARCHAR(100) NOT NULL,
  entity VARCHAR(100),
  entity_id INTEGER,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO restaurants (id, name, plan) VALUES (1, 'Restaurante Demo', 'pro')
ON CONFLICT (id) DO NOTHING;

INSERT INTO categories (restaurant_id, name) VALUES
  (1, 'Carnes'), (1, 'Verduras'), (1, 'Lácteos'), (1, 'Bebidas')
ON CONFLICT DO NOTHING;

INSERT INTO suppliers (restaurant_id, company_name, contact_name, phone, email) VALUES
  (1, 'Distribuciones García', 'Luis García', '600111222', 'luis@garciafood.com'),
  (1, 'Frescos del Norte', 'Marta Pérez', '600333444', 'marta@frescosnorte.com')
ON CONFLICT DO NOTHING;

INSERT INTO products (restaurant_id, category_id, supplier_id, name, sku, unit, purchase_price, stock_current, stock_min, location) VALUES
  (1, 1, 1, 'Solomillo de ternera', 'CAR-001', 'kg', 18.50, 0, 5, 'Cámara 1'),
  (1, 2, 2, 'Tomate pera', 'VER-001', 'kg', 2.10, 0, 3, 'Nevera 2'),
  (1, 3, 2, 'Queso manchego', 'LAC-001', 'kg', 14.00, 0, 4, 'Cámara 2'),
  (1, 4, 1, 'Vino tinto Rioja', 'BEB-001', 'ud', 6.80, 0, 10, 'Bodega')
ON CONFLICT DO NOTHING;

INSERT INTO recipes (restaurant_id, name, selling_price) VALUES
  (1, 'Solomillo a la pimienta', 22.00),
  (1, 'Ensalada de tomate', 8.50)
ON CONFLICT DO NOTHING;

INSERT INTO recipe_ingredients (recipe_id, product_id, quantity, unit) VALUES
  (1, 1, 0.25, 'kg'),
  (2, 2, 0.20, 'kg'),
  (2, 3, 0.05, 'kg')
ON CONFLICT DO NOTHING;
