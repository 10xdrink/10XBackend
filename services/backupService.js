// services/backupService.js

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { exec } = require('child_process');
const AWS = require('aws-sdk');

// Configure AWS S3 for cloud backups
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

/**
 * Perform a local database backup
 * @param {string} dbName - The name of the database to back up
 * @returns {Promise<string>} - The path to the backup file
 */
const backupDatabase = async (dbName) => {
  return new Promise((resolve, reject) => {
    const backupPath = path.join(__dirname, `../backups/${dbName}-${Date.now()}.gz`);
    const command = `mongodump --db ${dbName} --archive=${backupPath} --gzip`;

    exec(command, (error) => {
      if (error) {
        logger.error(`Database backup failed: ${error.message}`);
        return reject(error);
      }
      logger.info(`Database backup successful: ${backupPath}`);
      resolve(backupPath);
    });
  });
};

/**
 * Upload backup file to S3
 * @param {string} filePath - The path to the backup file
 * @param {string} bucketName - The S3 bucket name
 * @returns {Promise<void>}
 */
const uploadBackupToS3 = async (filePath, bucketName) => {
  try {
    const fileContent = fs.readFileSync(filePath);
    const params = {
      Bucket: bucketName,
      Key: path.basename(filePath),
      Body: fileContent,
      ACL: 'private',
    };

    await s3.upload(params).promise();
    logger.info(`Backup uploaded to S3: ${bucketName}/${params.Key}`);
  } catch (error) {
    logger.error(`Failed to upload backup to S3: ${error.message}`);
    throw error;
  }
};

/**
 * Perform a full backup and upload to S3
 * @param {string} dbName - The database name
 * @param {string} bucketName - The S3 bucket name
 */
const performFullBackup = async (dbName, bucketName) => {
  try {
    const backupPath = await backupDatabase(dbName);
    await uploadBackupToS3(backupPath, bucketName);
    logger.info('Full backup completed successfully');
  } catch (error) {
    logger.error(`Full backup process failed: ${error.message}`);
  }
};

module.exports = {
  performFullBackup,
  backupDatabase,
  uploadBackupToS3,
};
