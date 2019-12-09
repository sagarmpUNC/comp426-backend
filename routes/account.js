import express from "express";
import {authenticateUser} from "../middlewares/auth";
import bcrypt from 'bcryptjs';
import {userFilter} from "../filters/user";
import jwt from 'jsonwebtoken';

export const router = express.Router();
export const prefix = '/account';

const saltRounds = 10;

const {accountStore} = require('../data/DataStore');

const axios = require('axios');
import {secret} from "../secret";

/**
 * This route requires a valid JWT token.
 * This means that if you hit this route with a valid JWT then
 * you will be given the user data. If not, then you know you
 * know you are not logged in.
 */
router.get('/status', authenticateUser, function (req, res) {
  res.send(
    {
      user: {
        name: req.user.name,
        ...userFilter(accountStore.get(`users.${req.user.name}`))
      }
    }
  );
});

/**
 * Given a name and pass, validates a user
 * and returns a JWT.
 */
router.post('/login', async function (req, res) {
  if (!req.body.name || !req.body.pass || !req.body.recaptcha) {
    res.status(401).send({msg: 'Expected a payload of name, pass, and recaptcha.'});
    return;
  }

  const name = req.body.name.toLowerCase();
  const pass = req.body.pass;

  const recaptcha = req.body.recaptcha;
  if(!await checkReCaptcha(recaptcha)) {
    res.status(402).send({msg: `Failed reCAPTCHA.`});
    return;
  }

  let user = accountStore.get(`users.${name}`);
  if (!user) {
    res.status(401).send({msg: `User '${req.body.name}' is not a registered user.`});
    return;
  }
  const result = await checkUser(name, pass);
  if (!result) {
    res.status(401).send({msg: 'Bad username or password.'});
    return;
  }
  let userData = accountStore.get(`users.${name}.data`);
  const token = jwt.sign({
    name,
    data: userData
  }, process.env.SECRET_KEY, {expiresIn: '30d'});

  res.send({jwt: token, data: userData, name});
});

/**
 * Given a name and pass, will create a user
 * if one with that name doesn't exist in the
 * database.
 */
router.post('/create', async function (req, res) {
  if (!req.body.name || !req.body.pass || !req.body.recaptcha) {
    res.status(401).send({msg: 'Expected a payload of name, pass, and recaptcha.'});
    return;
  }

  const name = req.body.name.toLowerCase();
  const pass = req.body.pass;

  const recaptcha = req.body.recaptcha;
  if(!await checkReCaptcha(recaptcha)) {
    res.status(402).send({msg: `Failed reCAPTCHA.`});
    return;
  }

  let user = accountStore.get(`users.${name}`);
  if (user) {
    res.status(401).send({msg: `User '${req.body.name}' is already a registered user.`});
    return;
  }

  bcrypt.hash(pass, saltRounds, (err, hash) => {
    accountStore.set(`users.${name}`, {
      passwordHash: hash,
      data: req.body.data
    });
    res.send({data: userFilter(accountStore.get(`users.${name}`)), status: 'Successfully made account'});
  });

});


async function checkUser(username, password) {
  const user = accountStore.get(`users.${username}`);
  return await bcrypt.compare(password, user.passwordHash);
}

async function checkReCaptcha(recaptcha) {
  const result = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${recaptcha}`);
  // return false;
  return result.data.success;
}