require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors');

const { authenticateJWT, router: authRouter } = require('./modules/auth');
const filesRouter = require('./modules/files');

const app = express();

app.use(cors());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());

app.use('/', authRouter);
app.use('/file/', authenticateJWT,  filesRouter);

const port = 3500;
app.listen(port, () => {
    console.log(`Example app listening on port http://localhost:${port}`)
})

module.exports = app;
