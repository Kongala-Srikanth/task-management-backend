const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Initialize SQLite Database
const db = new sqlite3.Database('myDatabase.db', (err) => { // Create Database
    if (err) {
        console.error('Failed to connect to SQLite:', err.message);
        process.exit(1);
    }
    console.log('Connected to SQLite database');
});

const initializeTables = () => {
    db.serialize(() => {
        // Check and create userDetails table
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='userDetails';", (err, row) => {
            if (!row) {
                db.run(
                    `CREATE TABLE userDetails (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    );`,
                    (err) => {
                        if (err) {
                            console.error('Error creating userDetails table:', err.message); // Any error is occur during creating a table
                        } else {
                            console.log('userDetails table created.'); // When table is successfully created
                        }
                    }
                );
            } else {
                console.log('userDetails table already exists.'); // If userDetails table is doesn't exists
            }
        });

        // Check and create taskList table
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='taskList';", (err, row) => {
            if (!row) {
                db.run(
                    `CREATE TABLE taskList (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        userId INTEGER NOT NULL,
                        task TEXT NOT NULL,
                        status TEXT NOT NULL,
                        FOREIGN KEY (userId) REFERENCES userDetails(id)
                    );`,
                    (err) => {
                        if (err) {
                            console.error('Error creating taskList table:', err.message); // Any error is occur during creating a table
                        } else {
                            console.log('taskList table created.'); // When table is successfully created
                        }
                    }
                );
            } else {
                console.log('taskList table already exists.'); // If taskList table is doesn't exists
            }
        });
    });
};

// Initialize tables
initializeTables();

// Middleware for JWT verification
const middlewareJwtToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const jwtToken = authHeader && authHeader.split(' ')[1];

    if (!jwtToken) {
        return res.status(401).json({ errorMsg: 'Invalid JWT Token' });
    }

    jwt.verify(jwtToken, process.env.JWT_SECRET, (err, payload) => {
        if (err) {
            return res.status(401).json({ errorMsg: 'Invalid JWT Token' });
        }
        req.email = payload.email; 
        next();
    });
};

// API-1: Register a New User
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    db.get('SELECT * FROM userDetails WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ errorMsg: 'Database error' });
        }

        if (user) {
            return res.status(401).json({ errorMsg: 'User Already Exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO userDetails (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function (err) {
                if (err) {
                    return res.status(500).json({ errorMsg: 'Database error' });
                }
                res.status(201).json({ message: 'User Registered Successfully' });
            }
        );
    });
});

// API-2: User Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM userDetails WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ errorMsg: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ errorMsg: "User Doesn't Exist" });
        }

        const verifyPassword = await bcrypt.compare(password, user.password);
        if (!verifyPassword) {
            return res.status(401).json({ errorMsg: 'Incorrect Password' });
        }

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);
        res.status(201).json({ jwtToken: token });
    });
});

// API-3: Create a task
app.post('/tasks', middlewareJwtToken, (req, res) => {
    const { task, status } = req.body;

    db.get('SELECT id FROM userDetails WHERE email = ?', [req.email], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ errorMsg: 'Database error or user not found' });
        }

        db.run(
            'INSERT INTO taskList (userId, task, status) VALUES (?, ?, ?)',
            [user.id, task, status],
            function (err) {
                if (err) {
                    return res.status(500).json({ errorMsg: 'Database error' });
                }
                res.status(201).json({ message: 'task added successfully', taskId: this.lastID });
            }
        );
    });
});

// API-4: Update a task
app.put('/tasks/:id', middlewareJwtToken, (req, res) => {
    const { id } = req.params;
    const { task, status } = req.body;

    const updates = [];
    const params = [];

    if (task) {
        updates.push('task = ?');
        params.push(task);
    }
    if (status) {
        updates.push('status = ?');
        params.push(status);
    }

    if (updates.length === 0) {
        return res.status(400).json({ errorMsg: 'No valid fields to update' });
    }

    db.get('SELECT id FROM userDetails WHERE email = ?', [req.email], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ errorMsg: 'Database error or user not found' });
        }

        params.push(user.id, id);

        db.run(
            `UPDATE taskList SET ${updates.join(', ')} WHERE userId = ? AND id = ?`,
            params,
            function (err) {
                if (err) {
                    return res.status(500).json({ errorMsg: 'Database error' });
                }

                if (this.changes === 0) {
                    return res.status(404).json({ errorMsg: 'task not found' });
                }

                res.status(200).json({ message: 'task updated successfully' });
            }
        );
    });
});

// API-5: Delete a task
app.delete('/tasks/:id', middlewareJwtToken, (req, res) => {
    const { id } = req.params;

    db.get('SELECT id FROM userDetails WHERE email = ?', [req.email], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ errorMsg: 'Database error or user not found' });
        }

        db.run(
            'DELETE FROM taskList WHERE userId = ? AND id = ?',
            [user.id, id],
            function (err) {
                if (err) {
                    return res.status(500).json({ errorMsg: 'Database error' });
                }

                if (this.changes === 0) {
                    return res.status(404).json({ errorMsg: 'task not found' });
                }

                res.status(200).json({ message: 'task deleted successfully' });
            }
        );
    });
});

// API-6: Get tasks for User
app.get('/tasks', middlewareJwtToken, (req, res) => {
    db.get('SELECT id FROM userDetails WHERE email = ?', [req.email], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ errorMsg: 'Database error or user not found' });
        }

        db.all('SELECT * FROM taskList WHERE userId = ?', [user.id], (err, tasks) => {
            if (err) {
                return res.status(500).json({ errorMsg: 'Database error' });
            }
            res.status(200).json(tasks);
        });
    });
});

// API-7: Get User Profile
app.get('/profile', middlewareJwtToken, (req, res) => {
    db.get('SELECT * FROM userDetails WHERE email = ?', [req.email], (err, user) => {
        if (err) {
            return res.status(500).json({ errorMsg: 'Database error' });
        }
        res.status(200).json(user);
    });
});

const port = 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});


