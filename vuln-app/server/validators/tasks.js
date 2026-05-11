const Joi = require('joi');

const taskBodySchema = Joi.object({
  title: Joi.string().trim().min(1).max(200).required(),
  content: Joi.string().trim().max(2000).allow('').default(''),
  shared: Joi.boolean().truthy(1, '1', 'true').falsy(0, '0', 'false').default(false)
}).required().unknown(false);

const taskUpdateSchema = Joi.object({
  title: Joi.string().trim().min(1).max(200).optional(),
  content: Joi.string().trim().max(2000).allow('').optional(),
  shared: Joi.boolean().truthy(1, '1', 'true').falsy(0, '0', 'false').optional()
}).min(1).required().unknown(false);

const taskIdSchema = Joi.object({
  id: Joi.number().integer().positive().required()
}).required().unknown(false);

module.exports = {
  taskBodySchema,
  taskUpdateSchema,
  taskIdSchema
};