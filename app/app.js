const debug = require('debug')('app:main');
const express = require('express');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const path = require('path');
const morgan = require('morgan');

// read environnement variable in the ./.env file
require('dotenv').config();

// the main express app
const app = express();

// set global title and version for the whole app
app.locals.title = 'TIW4 - LOGON';
// mind that the following variables are only accessible if rjn with npm
app.locals.version = process.env.npm_package_version;
app.locals.name = process.env.npm_package_name;
app.locals.author_name = process.env.npm_package_author_name;
app.locals.description = process.env.npm_package_description;
app.locals.homepage = process.env.npm_package_homepage;

// use the https://ejs.co view engine.
// Embedded JavaScript templating.
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// see https://www.npmjs.com/package/morgan
// HTTP request logger middleware for node.js
// header 'x-forwarded-for' is set by nginx with the original requester's address
morgan.token('x-forwarded-for', function analyze(req, _res) {
  return req.headers['x-forwarded-for'];
});
if (process.env.NODE_ENV === 'development') {
  // dev = ":method :url :status :response-time ms - :res[content-length]"
  app.use(morgan('dev'));
} else {
  // combined  = ":remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent""
  app.use(morgan(`:x-forwarded-for - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"`));
}

// see https://expressjs.com/en/api.html#express.urlencoded
// to decode application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));

// see https://www.npmjs.com/package/cookie-parser
app.use(cookieParser());

// serve static content in ./public seen in ./ from the client's point of view
app.use(express.static(path.join(__dirname, 'public')));

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const loginRouter = require('./routes/login');
const signupRouter = require('./routes/signup');
const restrictedRouter = require('./routes/restricted');
const resetRouter = require('./routes/reset');

app.use('/', indexRouter);
app.use('/login', loginRouter);
app.use('/users', usersRouter);
app.use('/signup', signupRouter);
app.use('/restricted', restrictedRouter);
app.use('/reset',resetRouter);

// not found handler
app.use(function notFoundHandler(req, res, next) {
  debug(`handler 404: ${req.baseUrl}`);
  next(createError(404));
});

// error handler
app.use(function defaultHandler(err, req, res, _next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.status = err.status || 500;
  res.locals.error = process.env.NODE_ENV === 'development' ? err : {};

  debug(`rendering error: ${err}`);

  // set status (500 is default) and renders the error page
  res.status(res.locals.status);
  res.render('error');
});

module.exports = app;
