// seeds/tagSeeder.js

const mongoose = require('mongoose');
const dotenv = require('dotenv');
const connectDB = require('../config/db');
const Tag = require('../models/Tag');

// Load environment variables from .env file
dotenv.config();

// Seed Data: Define your tags here
const tags = [
  {
    name: 'Energy',
    description: 'Products that boost energy levels',
  },
  {
    name: 'Vegan',
    description: 'Products suitable for a vegan lifestyle',
  },
  {
    name: 'Organic',
    description: 'Certified organic products',
  },
  {
    name: 'Gluten-Free',
    description: 'Products that do not contain gluten',
  },
  {
    name: 'Low-Carb',
    description: 'Products low in carbohydrates',
  },
  {
    name: 'Dairy-Free',
    description: 'Products free from dairy ingredients',
  },
  {
    name: 'Sugar-Free',
    description: 'Products without added sugars',
  },
  {
    name: 'Non-GMO',
    description: 'Products that are non-genetically modified',
  },
  {
    name: 'Keto',
    description: 'Products suitable for the ketogenic diet',
  },
  {
    name: 'High-Protein',
    description: 'Products rich in protein',
  },
];

// Function to seed tags
const seedTags = async () => {
  try {
    // Connect to MongoDB
    await connectDB();

    // Clear existing tags (optional)
    // Uncomment the following line if you want to delete existing tags before seeding
    // await Tag.deleteMany();

    // Insert seed tags
    const createdTags = await Tag.insertMany(tags);
    console.log(`${createdTags.length} tags have been seeded successfully!`);

    // Close the database connection
    mongoose.connection.close();
    process.exit();
  } catch (error) {
    console.error(`Error seeding tags: ${error.message}`);
    mongoose.connection.close();
    process.exit(1);
  }
};

// Execute the seed function
seedTags();
