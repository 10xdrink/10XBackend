// seeds/seedProducts.js

const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Product = require('../models/Product'); // Adjust the path if necessary
const productsData = require('../data/Data.Dummy'); // Adjust the path if necessary

dotenv.config();

// Enhanced slugify function to generate URL-friendly slugs from product titles with unique identifiers
function slugify(text, id) {
  return (
    text
      .toString()
      .toLowerCase()
      .trim()
      .replace(/\s+/g, '-')           // Replace spaces with -
      .replace(/[^\w\-]+/g, '')       // Remove all non-word chars
      .replace(/\-\-+/g, '-')         // Replace multiple - with single -
    + '-' + id                         // Append the product id for uniqueness
  );
}

async function seedProducts() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Connected for Seeding');

    // Clear existing products
    await Product.deleteMany();
    console.log('Existing products cleared');

    // Generate slugs and prepare products for insertion
    const productsWithSlug = productsData.map((product) => {
      const slug = slugify(product.title, product.id);

      return {
        ...product,
        slug, // Add the generated slug
        // Ensure accordion data exists; if not, assign default values
        accordion: {
          details: product.accordion?.details || 'This is detailed information about the product.',
          shipping: product.accordion?.shipping || 'Shipping details go here.',
          returns: product.accordion?.returns || 'Return policy details go here.',
        },
        isActive: true,
        createdAt: new Date(),
      };
    });

    // Insert products into the database
    await Product.insertMany(productsWithSlug);
    console.log('Products seeded successfully');

    // Disconnect from MongoDB
    await mongoose.disconnect();
    process.exit();
  } catch (error) {
    console.error('Error during product seeding:', error);
    process.exit(1);
  }
}

seedProducts();
