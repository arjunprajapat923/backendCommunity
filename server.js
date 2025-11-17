import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import Stripe from 'stripe';
import UAParser from 'ua-parser-js';
import bodyParser from "body-parser"

dotenv.config();

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Middleware
// app.use(cors());
// Example for Express backend
app.use(cors({
    origin: 'https://communityhubb.vercel.app', // Replace with your Vercel URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());

// Database Connection
mongoose.connect(process.env.MONGODB_URI).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => console.log('MongoDB Error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  subscription: {
    plan: { type: String, enum: ['free', 'bronze', 'gold'], default: 'free' },
    stripeId: String,
    active: Boolean,
  },
  points: { type: Number, default: 0 },
  badges: [String],
  language: { type: String, default: 'en' },
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  mediaUrl: String,
  mediaType: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    createdAt: Date,
  }],
  shares: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const rewardSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  points: Number,
  reason: String,
  relatedPost: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  createdAt: { type: Date, default: Date.now },
});

const passwordResetSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  otp: String,
  expiresAt: Date,
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, expires: 3600 },
});

const loginHistorySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  browser: String,
  os: String,
  ip: String,
  device: String,
  timestamp: { type: Date, default: Date.now },
});

const pointTransferSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  points: Number,
  createdAt: { type: Date, default: Date.now },
});

// Models
const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Reward = mongoose.model('Reward', rewardSchema);
const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);
const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);
const PointTransfer = mongoose.model('PointTransfer', pointTransferSchema);

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Utility Functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateRandomPassword = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let password = '';
  for (let i = 0; i < 12; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({
      name,
      email,
      password: hashedPassword,
      phone,
    });

    await user.save();
    const token = createToken(user._id);
    res.json({ token, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).populate('friends');
    if (!user) return res.status(400).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid password' });

    // Track login
    const parser = new UAParser(req.headers['user-agent']);
    const result = parser.getResult();
    
    const loginLog = new LoginHistory({
      user: user._id,
      browser: result.browser.name,
      os: result.os.name,
      ip: req.ip,
      device: result.device.type || 'desktop',
    });
    await loginLog.save();

    const token = createToken(user._id);
    res.json({ token, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/user/profile', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const user = await User.findById(userId).populate('friends');
    if (!user) return res.status(400).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Password Reset Routes
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const reset = await PasswordReset.findOne({ user: user._id });
    if (reset && new Date() - reset.createdAt < 86400000) {
      return res.status(400).json({ error: 'Can only request once per day' });
    }

    const otp = generateOTP();
    const passwordReset = new PasswordReset({
      user: user._id,
      otp,
      expiresAt: new Date(Date.now() + 600000),
    });
    await passwordReset.save();

    await transporter.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP is: ${otp}`,
    });

    res.json({ message: 'OTP sent to email' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    const reset = await PasswordReset.findOne({ user: user._id });

    if (!reset || reset.otp !== otp || reset.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    await PasswordReset.deleteOne({ _id: reset._id });
    res.json({ message: 'OTP verified' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    const user = await User.findOne({ email });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Friend Management Routes
app.post('/api/friends/add', async (req, res) => {
  try {
    const { userId, friendId } = req.body;
    const user = await User.findById(userId);
    const friend = await User.findById(friendId);

    if (!friend) return res.status(400).json({ error: 'Friend not found' });
    if (user.friends.includes(friendId)) {
      return res.status(400).json({ error: 'Already friends' });
    }

    user.friends.push(friendId);
    friend.friends.push(userId);
    await user.save();
    await friend.save();

    res.json({ message: 'Friend added' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/friends/list', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const user = await User.findById(userId).populate('friends');
    res.json(user.friends);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Posts Routes
app.post('/api/posts', async (req, res) => {
  try {
    const { userId, content, mediaUrl, mediaType } = req.body;
    const user = await User.findById(userId);
    
    // Check posting limit
    const postsToday = await Post.countDocuments({
      author: userId,
      createdAt: { $gte: new Date(Date.now() - 86400000) }
    });

    const friendCount = user.friends.length;
    let maxPosts = 0;
    if (friendCount === 0) maxPosts = 0;
    else if (friendCount < 10) maxPosts = 2;
    else maxPosts = Infinity;

    if (postsToday >= maxPosts) {
      return res.status(400).json({ error: 'Post limit exceeded for today' });
    }

    const post = new Post({
      author: userId,
      content,
      mediaUrl,
      mediaType,
    });

    await post.save();
    await post.populate('author');
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find().populate('author').sort({ createdAt: -1 });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts/:postId/like', async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.headers['user-id'];
    const post = await Post.findById(postId);

    if (post.likes.includes(userId)) {
      post.likes = post.likes.filter(id => id.toString() !== userId);
    } else {
      post.likes.push(userId);
      // Award 1 point for liking
      const user = await User.findById(post.author);
      user.points += 1;
      await user.save();
    }

    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts/:postId/share', async (req, res) => {
  try {
    const { postId } = req.params;
    const post = await Post.findById(postId);
    post.shares = (post.shares || 0) + 1;

    // Award 2 points for share
    const user = await User.findById(post.author);
    user.points += 2;
    await user.save();

    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts/:postId/comment', async (req, res) => {
  try {
    const { postId } = req.params;
    const { userId, text } = req.body;
    const post = await Post.findById(postId);

    post.comments.push({
      user: userId,
      text,
      createdAt: new Date()
    });

    // Award 1 point for comment
    const user = await User.findById(post.author);
    user.points += 1;
    await user.save();

    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/posts/today-count', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const user = await User.findById(userId);
    const postsToday = await Post.countDocuments({
      author: userId,
      createdAt: { $gte: new Date(Date.now() - 86400000) }
    });

    const friendCount = user.friends.length;
    let maxPosts = 0;
    if (friendCount === 0) maxPosts = 0;
    else if (friendCount < 10) maxPosts = 2;
    else maxPosts = -1;

    res.json({ count: postsToday, maxPosts });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rewards Routes
app.post('/api/rewards/transfer', async (req, res) => {
  try {
    const { fromId, toId, points } = req.body;
    const fromUser = await User.findById(fromId);

    if (fromUser.points - points < 10) {
      return res.status(400).json({ error: 'Must keep minimum 10 points' });
    }

    if (points < 10) {
      return res.status(400).json({ error: 'Minimum 10 points to transfer' });
    }

    fromUser.points -= points;
    await fromUser.save();

    const toUser = await User.findById(toId);
    toUser.points += points;
    await toUser.save();

    const transfer = new PointTransfer({
      from: fromId,
      to: toId,
      points,
    });
    await transfer.save();

    res.json({ message: 'Points transferred' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/rewards/leaderboard', async (req, res) => {
  try {
    const leaderboard = await User.find().sort({ points: -1 }).limit(100);
    res.json(leaderboard);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/rewards/list', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const rewards = await Reward.find({ user: userId }).sort({ createdAt: -1 });
    res.json(rewards);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/rewards/check-badges', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const user = await User.findById(userId);

    const badges = [];
    if (user.points >= 50) badges.push('bronze');
    if (user.points >= 100) badges.push('silver');
    if (user.points >= 200) badges.push('gold');

    user.badges = badges;
    await user.save();

    res.json({ badges });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Subscription Routes
app.post('/api/subscription/create-checkout', async (req, res) => {
  try {
    const { plan, userId } = req.body;
    const user = await User.findById(userId);

    const prices = {
      free: 0,
      bronze: 30000,
      gold: 100000,
    };

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'inr',
            product_data: {
              name: `${plan.toUpperCase()} Plan`,
            },
            unit_amount: prices[plan],
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL}/subscription/success`,
      cancel_url: `${process.env.FRONTEND_URL}/subscription/cancel`,
      metadata: { userId, plan }
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// app.post('/api/subscription/webhook', async (req, res) => {
//   try {
//     const event = req.body;

//     if (event.type === 'checkout.session.completed') {
//       const session = event.data.object;
//       const userId = session.metadata.userId;
//       const plan = session.metadata.plan;

//       const user = await User.findById(userId);
//       user.subscription = {
//         plan,
//         stripeId: session.customer,
//         active: true
//       };
//       await user.save();
//     }

//     res.json({ received: true });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// Language and Login History Routes

// Stripe Webhook Route
app.post("/api/subscription/webhook",
  bodyParser.raw({ type: "application/json" }),
  (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("❌ Webhook Signature Error:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      
      console.log("Payment Success:", session.metadata);

      User.findByIdAndUpdate(
        session.metadata.userId,
        {
          subscription: {
            plan: session.metadata.plan,
            stripeId: session.customer,
            active: true,
          },
        },
        { new: true }
      )
        .then(() => console.log("Subscription updated"))
        .catch((err) => console.log("Update error:", err));
    }

    res.json({ received: true });
  }
);


app.post('/api/user/language', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const { language } = req.body;
    const user = await User.findByIdAndUpdate(userId, { language }, { new: true });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/user/login-history', async (req, res) => {
  try {
    const userId = req.headers['user-id'];
    const history = await LoginHistory.find({ user: userId }).sort({ timestamp: -1 }).limit(10);
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
