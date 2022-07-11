'use strict';

/**
 * user-language service.
 */

const { createCoreService } = require('@strapi/strapi').factories;

module.exports = createCoreService('api::user-language.user-language');
