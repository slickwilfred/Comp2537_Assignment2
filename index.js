// import required modules
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');


// variables
const app = express();
const port = process.env.PORT || 3020;
const expiration = 60 * 60 * 1000;
img1 = 'garfield.jpg';
img2 = 'tom.jpg';
im3 = 'sylvester.png';

// Private MongoDB and Node.js information stored in my .env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

// Private node session secret
// Encrypts the session ID - changes to this will invalidate the session
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { initDatabaseConnection } = require('./databaseConnection.js');
initDatabaseConnection()
  .then(database => {
    const userCollection = database.collection('users');

    const mongoStore = MongoStore.create({
      mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
      crypto: {
        secret: mongodb_session_secret
      }
    });


app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');


app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));


function isValidSession(req) {
  if (req.session.authenticated) {
      return true;
  }
  return false;
}

async function isAdmin(req) {
  const email = req.session.email;
  const user = await userCollection.findOne({ email: email });
  if (user && user.userType === 'admin') {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect('/login');
  }
}


async function adminValidation(req, res, next) {
  if (! (await isAdmin(req))) {
    res.status(403);
    res.render('error', { message: 'You are not authorized to view this page.' });
  } else {
    next();
  }
}

//Prevent NoSQL injection attacks
app.get('/nos1l-injection', async (req,res) => {
  var email = req.query.email;
  var password = req.query.password;

  if (!email || !password) {
		res.send(`<h3>no user provided - try /nosql-injection?email=name&password=pwd</h3> <h3>or /nosql-injection?email[$ne]=name&password[$ne]=pwd</h3>`);
    return;
  }
  
  console.log('email: ' + email);

  const emailSchema = Joi.string().max(20).required();
  const passwordSchema = Joi.string().max(20).required();
  const emailValidationResult = emailSchema.validate(email);
  const passwordValidationResult = passwordSchema.validate(password);

  if (emailValidationResult.error != null || passwordValidationResult.error != null) {  
    console.log(emailValidationResult.error);
      console.log(passwordValidationResult.error);
    res.send("<h1 style='color:darkred;'>Alert - NoSQL injection attack was detected. Go directly to jail, do not collect $200.</h1>");
    return;
 }	

 const result = await userCollection.find({email: email, password: password}).project({username: 1, password: 1, _id: 1}).toArray();

 console.log(result);

   res.send(`<h1>Hello ${email}</h1>`);
});

//Home route
app.get('/', (req,res) => {
  var name = req.session.name;
  var email = req.session.email;
 res.render('home', {email: email, name: name});
});

//Render the sign up page
app.get('/signup', (req,res) => {
  res.render('signup');
});

//Process the sign up request
app.post('/createUser', async (req,res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;
  const saltRounds = 10;

  if (!name) {
    res.send('Name is required. <a href="/signup">Try again</a>');
    return;
  }

  if (!email) {
    res.send('Email is required. <a href="/signup">Try again</a>');
    return;
  }

  if (!password) {
    res.send('Password is required. <a href="/signup">Try again</a>');
    return;
  }

  const schema = Joi.object({
    name: Joi.string().min(3).max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(3).max(20).required()
  });

  const validationResult = schema.validate({name: name, email: email, password: password});
  if (validationResult.error != null) {
    res.send('Invalid name, email, or password. <a href="/signup">Try again</a>');
    return;
  }

  const existingUser = await userCollection.findOne({email: email});
  if (existingUser != null) {
    res.send('This email is used by a pre-existing account. <a href="/signup">Try again</a>');
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({name: name, email: email, password: hashedPassword, userType: 'user'});
  console.log('User created');

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.userType = 'user';
  req.session.cookie.maxAge = expiration;
  res.redirect('/members');
});


//Render the log in page
app.get('/login', (req,res) => {
  if (req.session.authenticated) {
    res.render('login', {req: req, alreadyLoggedIn: true});
  } else{
    res.render('login', {req: req});

  }
});


//Login route
app.post('/loggingin', async (req,res) => {
  var email = req.body.email;
  var password = req.body.password;
  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect('/login?error=true');
    return;
  }

  const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();
  console.log(result);

  if (result.length != 1) {
    console.log('User does not exist');
    res.redirect('/login');
    return;
  }

  if (await bcrypt.compare(password, result[0].password)){
    console.log('User logged in');
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.email = email;
    req.session.cookie.maxAge = expiration;

    res.redirect('/members');
    return;
  } else {
    var html = `
    Incorrect password. <a href="/login">Try again</a>`
    res.send(html);
    return;
  }

});


//Admin Route
app.get('/admin', sessionValidation, adminValidation, async (req, res) => {
  try {
    const users = await userCollection.find({}).toArray();
    res.render('admin', { users });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/promote/:userId', sessionValidation, adminValidation, async (req, res) => {
  const userId = req.params.userId;
  const result = await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { userType: 'admin' } });
  console.log('User promoted to admin role.');
  res.redirect('/admin');
});

app.post('/demote/:userId', sessionValidation, adminValidation, async (req, res) => {
  const userId = req.params.userId; 
  const result = await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { userType: 'user' } });
  console.log('User demoted from admin role.');
  res.redirect('/admin');
});


//Members page route
app.get('/members', (req,res) => {
  const name = req.session.name;
  const email = req.session.email;
  img1 = 'garfield.jpg';
  img2 = 'tom.jpg';
  im3 = 'sylvester.png';
  if (!email) {
    res.redirect('/login');
  } else {
    res.render('members', {name: name, img1: 'garfield.jpg', img2: 'tom.jpg', img3: 'sylvester.png'});
  }
});

//Log out of account
app.post('/logout', (req,res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/');
    }
  });
});

//Serve static files
app.use(express.static(__dirname + '/public'));

//Handling 404 errors
//Catches everything that hasn't been processed by prior routes
app.get('*', (req,res) => {
  res.status(404).render('notFound');
});


    //Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  });
})
  .catch(error => {
    console.error("Failed to initialize database connection:", error);
  });
