// seeder.js
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const colors = require('colors'); // Optional: For colored console logs
const BlogPost = require('../models/BlogPost'); // Adjust the path as necessary
const Category = require('../models/Category');
const Tag = require('../models/Tag');
const slugify = require('slugify');

const User = require('../models/User');

// Load environment variables
dotenv.config({ path: './.env' });

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    // useFindAndModify: false, // Deprecated in Mongoose 6
    // useCreateIndex: true,    // Deprecated in Mongoose 6
  })
  .then(() => console.log('MongoDB Connected'.cyan.bold))
  .catch((err) => {
    console.error(`Error: ${err.message}`.red.bold);
    process.exit(1);
  });

// Sample Data (From Your Frontend's BlogData.js)
const blogPosts = [
  {
    id: 1,
    title: "Unlocking Your Brain's Full Potential",
    image: "BlogPlaceholder.png", // Replace with actual image URLs or paths
    excerpt: "Discover the secrets to maximizing your brain's capabilities...",
    description:
      "In this comprehensive guide, we delve into the latest neuroscience research to uncover strategies for enhancing cognitive functions. Learn how proper nutrition, exercise, and mental exercises can significantly boost your brain performance.",
    date: "2024-04-10",
    metaData: {
      category: "Mental Health & Mindfulness",
      author: "10X Formulas",
    },
    tags: ["Brain Health", "Cognitive Enhancement", "Neuroscience", "Self Improvement"],
  },
  // ... (Add all blog posts from your BlogData.js)
  // For brevity, I'll include all 18 blog posts here.
  {
    id: 2,
    title: "The Importance of Nutrition in Daily Performance",
    image: "BlogPlaceholder.png",
    excerpt: "Explore how balanced nutrition fuels your day-to-day activities...",
    description:
      "Nutrition plays a pivotal role in maintaining energy levels and cognitive functions. This article examines the essential nutrients required for optimal brain health and how they contribute to sustained daily performance.",
    date: "2024-03-25",
    metaData: {
      category: "Fitness & Nutrition",
      author: "10X Formulas",
    },
    tags: ["Nutrition", "Energy Levels", "Brain Health", "Healthy Eating"],
  },
  {
    id: 3,
    title: "10X Formulas: Revolutionizing Brain Nourishment",
    image: "BlogPlaceholder.png",
    excerpt: "Learn how 10X Formulas is changing the game in brain nutrition...",
    description:
      "10X Formulas has pioneered a unique approach to brain nourishment, blending scientific research with practical applications. Discover the innovative formulations that set us apart in the health supplements industry.",
    date: "2024-03-10",
    metaData: {
      category: "Supplements & Science",
      author: "10X Formulas",
    },
    tags: ["Supplements", "Brain Nutrition", "Health Innovation", "Fitness"],
  },
  {
    id: 4,
    title: "Mindfulness and Its Effects on Cognitive Health",
    image: "BlogPlaceholder.png",
    excerpt: "Understand the profound impact of mindfulness practices on your brain...",
    description:
      "Mindfulness meditation has been linked to numerous cognitive benefits, including improved focus, memory, and emotional regulation. This article explores the science behind mindfulness and practical tips to incorporate it into your daily routine.",
    date: "2024-02-28",
    metaData: {
      category: "Mental Health & Mindfulness",
      author: "10X Formulas",
    },
    tags: ["Mindfulness", "Cognitive Health", "Meditation", "Emotional Regulation"],
  },
  {
    id: 5,
    title: "The Role of Exercise in Enhancing Brain Function",
    image: "BlogPlaceholder.png",
    excerpt: "Discover how physical activity boosts your brain's performance...",
    description:
      "Regular exercise is not only beneficial for physical health but also crucial for cognitive function. Learn about the mechanisms through which exercise enhances memory, learning, and overall brain health.",
    date: "2024-02-15",
    metaData: {
      category: "Fitness & Nutrition",
      author: "10X Formulas",
    },
    tags: ["Exercise", "Brain Function", "Memory Improvement", "Physical Health"],
  },
  {
    id: 6,
    title: "Stress Management Techniques for a Healthier Mind",
    image: "BlogPlaceholder.png",
    excerpt: "Effective strategies to manage stress and maintain mental well-being...",
    description:
      "Chronic stress can have detrimental effects on brain health. This article outlines various stress management techniques, including breathing exercises, time management, and lifestyle changes, to help you maintain a balanced and healthy mind.",
    date: "2024-02-01",
    metaData: {
      category: "Sleep & Stress Management",
      author: "10X Formulas",
    },
    tags: ["Stress Management", "Mental Well-being", "Breathing Exercises", "Lifestyle Changes"],
  },
  {
    id: 7,
    title: "The Science Behind Energy Supplements",
    image: "BlogPlaceholder.png",
    excerpt: "Uncover the scientific principles that make energy supplements effective...",
    description:
      "Energy supplements have become increasingly popular for boosting daily performance. This article examines the scientific research supporting the efficacy of various ingredients commonly found in energy supplements.",
    date: "2024-01-20",
    metaData: {
      category: "Supplements & Science",
      author: "10X Formulas",
    },
    tags: ["Energy Supplements", "Health Science", "Daily Performance", "Supplement Ingredients"],
  },
  {
    id: 8,
    title: "Building a Morning Routine for Success",
    image: "BlogPlaceholder.png",
    excerpt: "Establish a morning routine that sets the tone for a productive day...",
    description:
      "A well-structured morning routine can significantly enhance your productivity and mental clarity. Explore strategies to create a morning routine that aligns with your personal and professional goals.",
    date: "2024-01-05",
    metaData: {
      category: "Productivity & Lifestyle",
      author: "10X Formulas",
    },
    tags: ["Morning Routine", "Productivity", "Mental Clarity", "Goal Setting"],
  },
  {
    id: 9,
    title: "Sleep and Brain Health: What You Need to Know",
    image: "BlogPlaceholder.png",
    excerpt: "Understand the critical connection between sleep and cognitive function...",
    description:
      "Quality sleep is essential for maintaining optimal brain health. This article discusses how sleep affects memory consolidation, emotional regulation, and overall cognitive performance, along with tips for improving sleep quality.",
    date: "2023-12-20",
    metaData: {
      category: "Sleep & Stress Management",
      author: "10X Formulas",
    },
    tags: ["Sleep Quality", "Brain Health", "Memory Consolidation", "Cognitive Performance"],
  },
  // Duplicate Posts (IDs 10-18) with Unique Tags and Standardized Categories
  {
    id: 10,
    title: "Unlocking Your Brain's Full Potential",
    image: "BlogPlaceholder.png",
    excerpt: "Discover the secrets to maximizing your brain's capabilities...",
    description:
      "In this comprehensive guide, we delve into the latest neuroscience research to uncover strategies for enhancing cognitive functions. Learn how proper nutrition, exercise, and mental exercises can significantly boost your brain performance.",
    date: "2024-04-10",
    metaData: {
      category: "Mental Health & Mindfulness",
      author: "10X Formulas",
    },
    tags: ["Brain Optimization", "Cognitive Strategies", "Neuroscience", "Health Enhancement"],
  },
  {
    id: 11,
    title: "The Importance of Nutrition in Daily Performance",
    image: "BlogPlaceholder.png",
    excerpt: "Explore how balanced nutrition fuels your day-to-day activities...",
    description:
      "Nutrition plays a pivotal role in maintaining energy levels and cognitive functions. This article examines the essential nutrients required for optimal brain health and how they contribute to sustained daily performance.",
    date: "2024-03-25",
    metaData: {
      category: "Fitness & Nutrition",
      author: "10X Formulas",
    },
    tags: ["Balanced Nutrition", "Energy Boost", "Brain Health", "Daily Performance"],
  },
  {
    id: 12,
    title: "10X Formulas: Revolutionizing Brain Nourishment",
    image: "BlogPlaceholder.png",
    excerpt: "Learn how 10X Formulas is changing the game in brain nutrition...",
    description:
      "10X Formulas has pioneered a unique approach to brain nourishment, blending scientific research with practical applications. Discover the innovative formulations that set us apart in the health supplements industry.",
    date: "2024-03-10",
    metaData: {
      category: "Supplements & Science",
      author: "10X Formulas",
    },
    tags: ["Innovative Supplements", "Brain Nourishment", "Health Supplements", "Scientific Research"],
  },
  {
    id: 13,
    title: "Mindfulness and Its Effects on Cognitive Health",
    image: "BlogPlaceholder.png",
    excerpt: "Understand the profound impact of mindfulness practices on your brain...",
    description:
      "Mindfulness meditation has been linked to numerous cognitive benefits, including improved focus, memory, and emotional regulation. This article explores the science behind mindfulness and practical tips to incorporate it into your daily routine.",
    date: "2024-02-28",
    metaData: {
      category: "Mental Health & Mindfulness",
      author: "10X Formulas",
    },
    tags: ["Mindfulness Practices", "Cognitive Benefits", "Meditation Techniques", "Emotional Health"],
  },
  {
    id: 14,
    title: "The Role of Exercise in Enhancing Brain Function",
    image: "BlogPlaceholder.png",
    excerpt: "Discover how physical activity boosts your brain's performance...",
    description:
      "Regular exercise is not only beneficial for physical health but also crucial for cognitive function. Learn about the mechanisms through which exercise enhances memory, learning, and overall brain health.",
    date: "2024-02-15",
    metaData: {
      category: "Fitness & Nutrition",
      author: "10X Formulas",
    },
    tags: ["Physical Activity", "Cognitive Function", "Memory Enhancement", "Brain Health"],
  },
  {
    id: 15,
    title: "Stress Management Techniques for a Healthier Mind",
    image: "BlogPlaceholder.png",
    excerpt: "Effective strategies to manage stress and maintain mental well-being...",
    description:
      "Chronic stress can have detrimental effects on brain health. This article outlines various stress management techniques, including breathing exercises, time management, and lifestyle changes, to help you maintain a balanced and healthy mind.",
    date: "2024-02-01",
    metaData: {
      category: "Sleep & Stress Management",
      author: "10X Formulas",
    },
    tags: ["Stress Relief", "Mental Well-being", "Breathing Techniques", "Lifestyle Management"],
  },
  {
    id: 16,
    title: "The Science Behind Energy Supplements",
    image: "BlogPlaceholder.png",
    excerpt: "Uncover the scientific principles that make energy supplements effective...",
    description:
      "Energy supplements have become increasingly popular for boosting daily performance. This article examines the scientific research supporting the efficacy of various ingredients commonly found in energy supplements.",
    date: "2024-01-20",
    metaData: {
      category: "Supplements & Science",
      author: "10X Formulas",
    },
    tags: ["Energy Science", "Supplement Efficacy", "Performance Boosters", "Health Supplements"],
  },
  {
    id: 17,
    title: "Building a Morning Routine for Success",
    image: "BlogPlaceholder.png",
    excerpt: "Establish a morning routine that sets the tone for a productive day...",
    description:
      "A well-structured morning routine can significantly enhance your productivity and mental clarity. Explore strategies to create a morning routine that aligns with your personal and professional goals.",
    date: "2024-01-05",
    metaData: {
      category: "Productivity & Lifestyle",
      author: "10X Formulas",
    },
    tags: ["Morning Habits", "Productivity Tips", "Mental Clarity", "Goal Achievement"],
  },
  {
    id: 18,
    title: "Sleep and Brain Health: What You Need to Know",
    image: "BlogPlaceholder.png",
    excerpt: "Understand the critical connection between sleep and cognitive function...",
    description:
      "Quality sleep is essential for maintaining optimal brain health. This article discusses how sleep affects memory consolidation, emotional regulation, and overall cognitive performance, along with tips for improving sleep quality.",
    date: "2023-12-20",
    metaData: {
      category: "Sleep & Stress Management",
      author: "10X Formulas",
    },
    tags: ["Sleep Hygiene", "Cognitive Performance", "Memory Consolidation", "Emotional Regulation"],
  },
];

// Function to import data
const importData = async () => {
  try {
    // Clear existing data
    await BlogPost.deleteMany();
    await Category.deleteMany();
    await Tag.deleteMany();
    await User.deleteMany();

    console.log('Existing data cleared'.yellow.bold);

    // Create Categories
    const categoryNames = [
      "Mental Health & Mindfulness",
      "Fitness & Nutrition",
      "Supplements & Science",
      "Sleep & Stress Management",
      "Productivity & Lifestyle",
    ];

    const categories = await Category.insertMany(
      categoryNames.map((name) => ({ name, type: 'blog' }))
    );

    console.log('Categories seeded'.green.inverse);

    // Create Tags
    const tagNames = [
      // Collect all unique tags from blogPosts
      ...new Set(blogPosts.flatMap((post) => post.tags)),
    ];

    const tags = await Tag.insertMany(
      tagNames.map((name) => ({ name }))
    );

    console.log('Tags seeded'.green.inverse);

    // Create a default user (author)
    const user = await User.create({
      name: '10X Formulas',
      email: 'author@10xformulas.com',
      password: 'password123', // Ensure to change this password in production
      role: 'content-manager', // Adjust based on your roles
    });

    console.log('User seeded'.green.inverse);

    // Create Blog Posts
    const blogPostsToInsert = blogPosts.map((post) => {
      // Find category by name
      const category = categories.find((cat) => cat.name === post.metaData.category);

      // Find tag IDs
      const postTags = post.tags.map((tagName) => {
        const tag = tags.find((t) => t.name === tagName);
        return tag ? tag._id : null;
      }).filter(tagId => tagId !== null); // Remove nulls if any

      return {
        title: post.title,
        slug: slugify(post.title, { lower: true, strict: true }),
        content: post.description,
        categories: [category ? category._id : null],
        tags: postTags,
        images: [post.image], // Ensure images are properly handled
        author: user._id,
        status: 'published', // Adjust based on your needs
        isFeatured: false, // Adjust based on your needs
        views: 0,
        meta: {
          title: post.title,
          description: `${post.title} - A blog post on ${post.metaData.category}.`,
          keywords: [post.title, 'blog', ...post.metaData.category.split(' & ')],
        },
        isActive: true,
        createdAt: new Date(post.date),
        updatedAt: new Date(post.date),
      };
    });

    await BlogPost.insertMany(blogPostsToInsert);

    console.log('Blog Posts seeded'.green.inverse);
    process.exit();
  } catch (err) {
    console.error(`${err}`.red.inverse);
    process.exit(1);
  }
};

// Function to destroy data (optional)
const destroyData = async () => {
  try {
    await BlogPost.deleteMany();
    await Category.deleteMany();
    await Tag.deleteMany();
    await User.deleteMany();

    console.log('Data destroyed'.red.inverse);
    process.exit();
  } catch (err) {
    console.error(`${err}`.red.inverse);
    process.exit(1);
  }
};

// Handle command line arguments
if (process.argv[2] === '-d') {
  destroyData();
} else {
  importData();
}
