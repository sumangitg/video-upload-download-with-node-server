const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path=require('path');



const app = express();
const port = 3000;

// express middleware to parse urlencoded or json data
app.use(express.urlencoded({extended:true}));
app.use(express.json());

// middleware to set up ejs view engine
app.set('views', path.join(__dirname,'views'));
app.set('view engine' , 'ejs');

//middleware to server static files from public folder
app.use(express.static('public'));


const db=mysql.createConnection({
  password: 'hal987@@@',
  user:'root',
  host:'localhost',
  database:'authentication'
})

db.connect((err)=>{
  if(err){
    console.error("database not connected", err);
  }
  else{
    console.log("database is connected");
  }
})



// Express middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: 'your_secret_key',
    resave: true,
    saveUninitialized: true,
  })
);



// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.user && req.session.token) {
    jwt.verify(req.session.token, 'your_jwt_secret', (err, decoded) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = decoded;
      next();
    });
  } else {
    res.redirect('/login');
  }
}





app.get('/', (req,res)=>{
  res.render('index');
})


app.get('/register', (req,res)=>{
  res.render('register');
})



// Login Page
app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/welcome',(req,res)=>{
  res.render('welcome');
})



app.post('/login', async (req, res) => {
  const { userName, userPassword } = req.body;

  // Check if userName exists
  const user = await new Promise((resolve, reject) => {
    db.query(
      'SELECT * FROM Users WHERE userName = ?',
      [userName],
      (err, result) => {
        if (err) reject(err);
        resolve(result[0]);
      }
    );
  });

  if (!user) {
    res.send('Invalid username. <a href="/register">Register</a>');
  } else {
    // Check password
    const passwordMatch = await bcrypt.compare(userPassword, user.userPassword);

    if (passwordMatch) {
      // Create JWT token
      const token = jwt.sign({ userId: user.userId, userName: user.userName }, 'your_jwt_secret', {
        expiresIn: '1h', // Set token expiration time
      });

      // Save token in session and cookie
      req.session.token = token;
      res.cookie('token', token, { maxAge: 3600000, httpOnly: true });

      res.redirect('/welcome');
    } else {
      res.send('Incorrect password. <a href="/login">Login</a>');
    }
  }
});





app.post('/register', async (req, res) => {
  const { userName, userPassword } = req.body;

  // Check if userName already exists
  const userExists = await new Promise((resolve, reject) => {
    db.query(
      'SELECT * FROM Users WHERE userName = ?',
      [userName],
      (err, result) => {
        if (err) reject(err);
        resolve(result.length > 0);
      }
    );
  });

  if (userExists) {
    res.send('Account already exists with this username. <a href="/login">Login</a>');
  } else {
    // Hash the password
    const hashedPassword = await bcrypt.hash(userPassword, 10);

    // Store the user in the database
    db.query(
      'INSERT INTO Users (userName, userPassword) VALUES (?, ?)',
      [userName, hashedPassword],
      (err) => {
        if (err) throw err;
        res.redirect('/login');  
      }
    );
  }
});




// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('token');
  res.redirect('/');
});







app.listen(port, ()=>{
  console.log(`suman server is running on https://localhost:${port}`);
})
