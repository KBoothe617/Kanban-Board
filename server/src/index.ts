import * as dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import sequelize from './db';

const app = express();

// Test the database connection
sequelize.authenticate()
  .then(() => console.log('Database connected...'))
  .catch(err => console.log('Error: ' + err));

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});