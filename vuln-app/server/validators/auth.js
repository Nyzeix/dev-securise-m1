const Joi = require('joi');

const registerSchema = Joi.object({
  email: Joi.string().email().max(254).required(),
  password: Joi.string().min(12).max(128).required()
}).required().unknown(false);

const loginSchema = Joi.object({
  email: Joi.string().email().max(254).required(),
  password: Joi.string().min(1).max(128).required()
}).required().unknown(false);

function validateRegisterBody(body) {
  return registerSchema.validate(body, { abortEarly: false, convert: true });
}

function validateLoginBody(body) {
  return loginSchema.validate(body, { abortEarly: false, convert: true });
}

module.exports = { registerSchema, loginSchema, validateRegisterBody, validateLoginBody };