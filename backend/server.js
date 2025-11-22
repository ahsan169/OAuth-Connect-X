import express from "express";
import session from "express-session";
import passport from "passport";
import OAuth2Strategy from "passport-oauth2";
import mongoose from "mongoose";
import cors from "cors";
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";
import crypto from "crypto";
import base64url from "base64url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

// logging
const log = {
  auth: (msg, data) => console.log(`[Auth] ${msg}`, data || ""),
  error: (msg, err) => console.error(`[Error] ${msg}:`, err),
  session: (msg, data) => console.log(`[Session] ${msg}`, data || ""),
  pkce: (msg, data) => console.log(`[PKCE] ${msg}`, data || ""),
  oauth: (msg, data) => console.log(`[OAuth] ${msg}`, data || ""),
};

// PKCE Helper Functions
function generateCodeVerifier() {
  const verifier = crypto.randomBytes(32).toString("hex");
  return base64url.fromBase64(Buffer.from(verifier).toString("base64"));
}

async function generateCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64url.fromBase64(hash.toString("base64"));
}

const app = express();

// MongoDB Connection
await mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => log.auth("Connected to MongoDB"))
  .catch((err) => log.error("MongoDB connection error", err));

// User Model
const UserSchema = new mongoose.Schema({
  twitterId: String,
  username: String,
  displayName: String,
  profileImageUrl: String,
  accessToken: String,
  refreshToken: String,
  connectedAt: Date,
});

const User = mongoose.model("User", UserSchema);

// Middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Store PKCE challenge
app.use(async (req, res, next) => {
  if (!req.session.pkce) {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    req.session.pkce = {
      verifier,
      challenge,
    };
    log.pkce("Generated PKCE", { verifier, challenge });
  }
  next();
});

class TwitterOAuth2Strategy extends OAuth2Strategy {
  constructor(options, verify) {
    super(options, verify);
    this.name = "twitter";

    // Configure OAuth2 for Twitter
    this._oauth2.useAuthorizationHeaderforGET(true);

    // Set up the authorization header
    const credentials = Buffer.from(
      `${options.clientID}:${options.clientSecret}`
    ).toString("base64");
    this._oauth2._customHeaders = {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    };
  }

  // Override the getOAuthAccessToken
  getOAuthAccessToken(code, params, callback) {
    const credentials = Buffer.from(
      `${this._oauth2._clientId}:${this._oauth2._clientSecret}`
    ).toString("base64");

    const options = {
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    };

    const postParams = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: this._oauth2._redirectUri,
      code_verifier: params.code_verifier,
      client_id: this._oauth2._clientId,
    };

    const post_data = Object.entries(postParams)
      .map(
        ([key, value]) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
      )
      .join("&");

    const parseResponse = (error, data, response) => {
      if (error) {
        console.error("Token Error:", error);
        return callback(error);
      }

      let results;
      try {
        results = JSON.parse(data);
      } catch (e) {
        return callback(e);
      }

      const access_token = results.access_token;
      const refresh_token = results.refresh_token;
      callback(null, access_token, refresh_token, results);
    };

    this._oauth2._request(
      "POST",
      this._oauth2._getAccessTokenUrl(),
      options.headers,
      post_data,
      null,
      parseResponse
    );
  }

  // Override authorizationParams to include PKCE
  authorizationParams(options) {
    return {
      code_challenge: options.pkce.challenge,
      code_challenge_method: "S256",
      client_id: this._oauth2._clientId,
    };
  }

  // Override tokenParams to include PKCE verifier
  tokenParams(options) {
    return {
      code_verifier: options.pkce.verifier,
      client_id: this._oauth2._clientId,
    };
  }
}

// Twitter OAuth Configuration
passport.use(
  new TwitterOAuth2Strategy(
    {
      authorizationURL: "https://twitter.com/i/oauth2/authorize",
      tokenURL: "https://api.twitter.com/2/oauth2/token",
      clientID: process.env.TWITTER_CLIENT_ID,
      clientSecret: process.env.TWITTER_CLIENT_SECRET,
      callbackURL: process.env.TWITTER_CALLBACK_URL,
      scope: ["tweet.read", "users.read", "follows.read", "offline.access"],      
      state: true,
    },
    async (accessToken, refreshToken, params, profile, done) => {
      try {
        log.oauth("Token received", {
          hasAccessToken: !!accessToken,
          hasRefreshToken: !!refreshToken,
          params,
        });

        const response = await fetch(
          "https://api.twitter.com/2/users/me?user.fields=profile_image_url",
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        );

        if (!response.ok) {
          const errorText = await response.text();
          log.error("Twitter API error", {
            status: response.status,
            error: errorText,
          });
          throw new Error(`Twitter API error: ${errorText}`);
        }

        const userData = await response.json();
        log.oauth("User data received", userData);

        let user = await User.findOne({ twitterId: userData.data.id });

        if (!user) {
          user = await User.create({
            twitterId: userData.data.id,
            username: userData.data.username,
            displayName: userData.data.name,
            profileImageUrl: userData.data.profile_image_url,
            accessToken,
            refreshToken,
            connectedAt: new Date(),
          });
          log.oauth("Created new user", { id: user._id });
        } else {
          user.accessToken = accessToken;
          user.refreshToken = refreshToken;
          user.connectedAt = new Date();
          await user.save();
          log.oauth("Updated existing user", { id: user._id });
        }

        return done(null, user);
      } catch (error) {
        log.error("OAuth callback error", error);
        return done(error);
      }
    }
  )
);

// PKCE Parameters middleware
TwitterOAuth2Strategy.prototype.authorizationParams = function (options) {
  return {
    code_challenge: options.pkce.challenge,
    code_challenge_method: "S256",
  };
};

TwitterOAuth2Strategy.prototype.tokenParams = function (options) {
  return {
    code_verifier: options.pkce.verifier,
  };
};

passport.serializeUser((user, done) => {
  log.auth("Serializing user", { id: user._id });
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    log.auth("Deserialized user", { id, found: !!user });
    done(null, user);
  } catch (error) {
    log.error("Deserialize error", error);
    done(error);
  }
});

// Routes
app.get("/connect/twitter", (req, res, next) => {
  log.oauth("Starting Twitter connection", { session: !!req.session });
  passport.authenticate("twitter", {
    pkce: {
      verifier: req.session.pkce.verifier,
      challenge: req.session.pkce.challenge,
    },
  })(req, res, next);
});

app.get("/connect/twitter/callback", (req, res, next) => {
  console.log("Full callback request:", {
    query: req.query,
    pkce: req.session?.pkce,
    headers: req.headers,
  });

  passport.authenticate("twitter", {
    pkce: {
      verifier: req.session.pkce.verifier,
    },
    successRedirect: "http://localhost:5173",
    failureRedirect: "http://localhost:5173?error=1",
  })(req, res, (err) => {
    if (err) {
      console.error("Detailed authentication error:", err);
      return res.redirect(
        `http://localhost:5173?error=${encodeURIComponent(err.message)}`
      );
    }
    next();
  });
});

app.get("/api/connections/twitter", (req, res) => {
  if (!req.user) {
    return res.json({ connected: false });
  }

  res.json({
    connected: true,
    data: {
      username: req.user.username,
      displayName: req.user.displayName,
      profileImageUrl: req.user.profileImageUrl,
      connectedAt: req.user.connectedAt,
    },
  });
});

app.post("/disconnect/twitter", async (req, res) => {
  try {
    if (!req.user) {
      return res.status(404).json({ error: "User not found" });
    }

    await User.findByIdAndDelete(req.user._id);
    req.logout(() => {
      res.json({ message: "Twitter account disconnected successfully" });
    });
  } catch (error) {
    log.error("Disconnect error", error);
    res.status(500).json({ error: "Failed to disconnect account" });
  }
});

app.get("/api/twitter/followers", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    // Get the access token from the database
    const accessToken = req.user.accessToken;

    // request to Twitter API v2 followers endpoint
    const response = await fetch(
      "https://api.twitter.com/2/users/me/followers?max_results=10",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    // Check if token might be expired
    if (response.status === 401) {
      // Token expired, need to refresh
      const newTokens = await refreshTwitterToken(req.user.refreshToken);

      // Update user's tokens in database
      await User.findByIdAndUpdate(req.user._id, {
        accessToken: newTokens.access_token,
        refreshToken: newTokens.refresh_token,
      });

      // Retry the request with new token
      const retryResponse = await fetch(
        "https://api.twitter.com/2/users/me/followers?max_results=10",
        {
          headers: {
            Authorization: `Bearer ${newTokens.access_token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const retryData = await retryResponse.json();
      return res.json(retryData);
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Error fetching followers:", error);
    res.status(500).json({ error: "Failed to fetch followers" });
  }
});

// helper function to handle token refresh
async function refreshTwitterToken(refreshToken) {
    try {
      console.log("Attempting to refresh token...");
      
      // Create Basic auth header with client credentials
      const credentials = Buffer.from(
        `${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`
      ).toString('base64');
  
      const response = await fetch("https://api.twitter.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Basic ${credentials}`
        },
        body: new URLSearchParams({
          refresh_token: refreshToken,
          grant_type: "refresh_token",
          client_id: process.env.TWITTER_CLIENT_ID
        }).toString()
      });
  
      const responseText = await response.text();
      console.log("Refresh token response:", {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: responseText
      });
  
      if (!response.ok) {
        throw new Error(`Failed to refresh token: ${response.status} - ${responseText}`);
      }
  
      try {
        return JSON.parse(responseText);
      } catch (e) {
        console.error("Error parsing refresh token response:", e);
        throw new Error(`Invalid JSON response: ${responseText}`);
      }
    } catch (error) {
      console.error("Detailed refresh token error:", {
        message: error.message,
        stack: error.stack,
        refreshToken: refreshToken ? "exists" : "missing"
      });
      throw error;
    }
  }

  app.get("/api/twitter/following", async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: "Not authenticated" });
      }
  
      if (!req.user.accessToken) {
        return res.status(401).json({ error: "No access token found" });
      }
  
      const accessToken = req.user.accessToken;

      console.log(accessToken);
      console.log(
        "-0----------------------------------------------------\n\n\n\n\n"
      );
  
      const response = await fetch(
        "https://api.twitter.com/2/users/me/following?max_results=10",
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
        }
      );

      console.log(response);
      console.log(
        "-0----------------------------------------------------\n\n\n\n\n"
      );

  
      if (response.status === 401) {
        try {
          console.log("Token expired, attempting refresh...");
          if (!req.user.refreshToken) {
            throw new Error("No refresh token available");
          }
  
          const newTokens = await refreshTwitterToken(req.user.refreshToken);
          
          await User.findByIdAndUpdate(req.user._id, {
            accessToken: newTokens.access_token,
            refreshToken: newTokens.refresh_token,
          });
  
          const retryResponse = await fetch(
            "https://api.twitter.com/2/users/me/following?max_results=10",
            {
              headers: {
                Authorization: `Bearer ${newTokens.access_token}`,
                "Content-Type": "application/json",
              },
            }
          );
  
          if (!retryResponse.ok) {
            throw new Error(`Retry failed: ${retryResponse.status}`);
          }
  
          const retryData = await retryResponse.json();
          return res.json(retryData);
        } catch (refreshError) {
          console.error("Token refresh failed:", refreshError);
          return res.status(401).json({ 
            error: "Authentication expired. Please reconnect your Twitter account.",
            details: refreshError.message
          });
        }
      }
  
      if (!response.ok) {
        throw new Error(`Twitter API error: ${response.status}`);
      }
  
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("Error fetching following:", error);
      res.status(500).json({ 
        error: "Failed to fetch following",
        details: error.message 
      });
    }
  });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
