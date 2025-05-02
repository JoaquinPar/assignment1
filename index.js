require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const path = require('path');
const { PassThrough } = require('stream');
const app = express();

app.set('view engine', 'ejs');

const port = 8000;
app.use(express.urlencoded({extended: false}));

/*
MongoDB Connection
 */
const MongoClient = require('mongodb').MongoClient;
const atlasURI = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;
let database;
async function connectToMongoDB() {
    const mongoDBConnection = await MongoClient.connect(atlasURI, {});
    database = mongoDBConnection.db("users");
}
connectToMongoDB();

// let mongoDBConnection = new MongoClient(atlasURI, {});
// const users = database.db(process.env.MONGODB_DATABASE).collection('users');
// let mongoStore = MongoStore.create({
//     mongoUrl: atlasURI,
//     crypto: {
//         secret: process.env.MONGODB_SESSION_SECRET
//     }
// })

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    saveUninitialized: false,
    resave: true,
    store: new MongoStore({
        mongoUrl: atlasURI,
        autoRemove: 'native'
    })
}
));

app.get('/', (req, res) => {
    if(req.session.authenticated) {
        res.render('index', {
            title: "Still Logged In",
            filename: '../partials/landingSignedIn',
            user: { name: req.session.username }
        });
    } else {
        res.render('index', {title: "Landing Page", filename: '../partials/landingNoSignIn'});
    }
});

app.get('/signup', (req, res) => {
    res.render('index', {title: "Sign up", filename: '../partials/signup'});
});

app.get('/login', (req, res) => {
    res.render('index', {
        title: "Login",
        filename: '../partials/login',
        error: { name: req.session.loginFailed }
    });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    } else {
        res.render('index', {
            title: "Members",
            filename: '../partials/members',
            user: { name: req.session.username }
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net']}}),
        password: Joi.string().max(20).required()
    });

    const validData = schema.validate(req.body);

    if (validData.error != null) {
        console.log(validData.error);
        res.redirect('/signup');
        return;
    }

    let hashedPassword = await bcrypt.hash(req.body.password, 12);

    database.collection('users').insertOne({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword
    });

    req.session.username = req.body.username;
    req.session.authenticated = true;
    req.session.cookie.expires = 3600000;

    res.redirect('/members');
});

app.post('/login', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net']}}),
        password: Joi.string().max(20).required()
    });

    const validData = schema.validate(req.body);

    if (validData.error != null) {
        return res.redirect('/login');
        
    }

    let username;
    let password;

    await database.collection('users').findOne({email: req.body.email}).then((user) => {
        if (!user) {
            req.session.authenticated = false;
            req.session.loginFailed = 'email';
            return res.redirect('/login');
        } else {
            password = user.password;
            username = user.username;
        }
    });

    if (await bcrypt.compare(req.body.password, password)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.expires = 3600000;
        delete req.session.loginFailed;
        return res.redirect('/members');
    } else {
        req.session.authenticated = false;
        req.session.loginFailed = 'password';
        return res.redirect('/login');
    }

    
});

app.get('/*splat', (req, res) => {
    res.status(404);
    res.send('404 Not Found');
});

app.listen(port, () => {
    console.log('Running express server');
});