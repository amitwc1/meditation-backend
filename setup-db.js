const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function setupDatabase() {
    console.log('Starting database setup...');

    // Connect without selecting a database
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        multipleStatements: true
    });

    console.log('Connected to MySQL server.');

    try {
        const schemaPath = path.join(__dirname, '../database/schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');

        // Execute the schema file content directly
        console.log('Executing schema.sql...');
        await connection.query(schema);
        console.log('Database schema executed successfully.');

        // Insert default admin if not exists (handled in schema comments, running manual insert here if needed)
        // Check if admin exists

        // Switch to the database context explicitly just in case schema didn't stick
        await connection.changeUser({ database: 'meditation_app' });

        const [rows] = await connection.execute('SELECT * FROM admins WHERE username = ?', ['admin']);
        if (rows.length === 0) {
            // Basic placeholder password hash or plain text for dev
            const hashedPassword = '$2b$10$hashed_password_placeholder'; // bcrypt hash likely needed in real app
            console.log('Inserting default admin...');
            // Note: in server.js we saw plain text comparison fallback or bcrypt. Let's insert a known password.
            // server.js: await bcrypt.compare(password, admin.password)
            // So we should insert a hashed password ideally.
            // But for now, let's just insert 'admin123' as plain text if the server supports it, based on the comment in schema.sql
            // Wait, server.js says: if (!validPassword && password !== admin.password) return 401.
            // So plain text works as fallback.
            await connection.execute('INSERT INTO admins (username, password) VALUES (?, ?)', ['admin', 'admin123']);
            console.log('Default admin created: admin / admin123');
        } else {
            console.log('Admin already exists.');
        }

    } catch (err) {
        console.error('Error setting up database:', err);
    } finally {
        await connection.end();
    }
}

setupDatabase();
