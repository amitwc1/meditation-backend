const mysql = require('mysql2/promise');
require('dotenv').config();

async function checkDatabase() {
    console.log('Checking database connection...');
    try {
        // First try to connect to the server without selecting a DB
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || ''
        });
        console.log('Connected to MySQL server successfully.');

        // Check if database exists
        const [rows] = await connection.execute(`SHOW DATABASES LIKE '${process.env.DB_NAME || 'meditation_app'}'`);
        if (rows.length === 0) {
            console.log(`Database '${process.env.DB_NAME || 'meditation_app'}' does not exist.`);
            console.log('Creating database...');
            await connection.execute(`CREATE DATABASE ${process.env.DB_NAME || 'meditation_app'}`);
            console.log('Database created.');
        } else {
            console.log(`Database '${process.env.DB_NAME || 'meditation_app'}' exists.`);
        }

        await connection.end();

        // Now connect with DB selected and check tables
        const dbConnection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'meditation_app'
        });

        const [tables] = await dbConnection.execute('SHOW TABLES');
        console.log('Tables in database:', tables);

        await dbConnection.end();

    } catch (err) {
        console.error('Database connection error:', err);
    }
}

checkDatabase();
