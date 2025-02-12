// services/templateService.js

const fs = require('fs');
const path = require('path');
const handlebars = require('handlebars'); // Ensure this line is present
const logger = require('../utils/logger');

/**
 * Load and compile an HTML template with Handlebars
 * @param {string} templateName - Name of the template file (e.g., 'passwordReset.html')
 * @param {Object} data - Data to inject into the template
 * @returns {string} - Compiled HTML content
 */
const compileTemplate = (templateName, data) => {
  try {
    const templatePath = path.join(__dirname, '../templates', templateName);
    logger.info(`Compiling template from path: ${templatePath}`);
    const templateSource = fs.readFileSync(templatePath, 'utf8');
    const template = handlebars.compile(templateSource);
    return template(data);
  } catch (error) {
    logger.error(`Error compiling template ${templateName}:`, error);
    throw new Error('Template compilation failed');
  }
};

module.exports = { compileTemplate };
