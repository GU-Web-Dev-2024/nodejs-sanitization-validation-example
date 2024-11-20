//Sanitizing data
//modifications to sanitize data before accessing the database
//https://medium.com/@SW_Integrity/mongodb-preventing-common-vulnerabilities-in-the-mean-stack-ac27c97198ec
//https://www.npmjs.com/package/mongo-sanitize
//https://thecodebarbarian.wordpress.com/2014/09/04/defending-against-query-selector-injection-attacks/
//https://severalnines.com/database-blog/securing-mongodb-external-injection-attacks

//1. npm install mongo-sanitize
//2. require "mongo-sanitize"
//3. pass parameters to the sanitize function to strip query parameters
//      i.e. "make them safe" against query selector injection attacks
//4. use the sanitized parameters instead of the parameters passed into
//   the function

//Validating data
//https://www.npmjs.com/package/validatorjs
//https://blog.logrocket.com/how-to-handle-data-validation-in-node-using-validatorjs/

//1. npm install validatorjs
//2. require "validatorjs"
//3. define rules for your data
//4. instantiate a new instance of your validator and pass it your data and rules
//5. make decisions based on the results

//Data Sanitization
const sanitize = require("mongo-sanitize"); //2.

//Data Validation
const Validator = require("validatorjs"); //2.

//3. we define an object that is used to match rules for our data
//note that if we omit a property it is automatically validated
var rules = {
    name: "required|min3",
    password: "required|min:5",
    jobTitle: "string",
    //other examples
    //email: 'required|email',
    //age: 'min:18'
};

//END VALIDATION BLOCK

// Load environment variables from the .env file
// Environment variables are used to securely store sensitive data like the JWT secret and database connection string.
require("dotenv").config();

// Import required modules
const express = require("express"); // Framework to build web applications
const mongoose = require("mongoose"); // Library to interact with MongoDB
const jwt = require("jwt-simple"); // Library to create and decode JSON Web Tokens
const path = require("path"); // Node.js module for handling file and directory paths

// Import bcrypt for password hashing and comparison
// bcrypt is a library to securely hash and verify passwords.
const bcrypt = require("bcryptjs");

// Create an Express application
// This is the main application object for handling HTTP requests and responses.
const app = express();

// Create a router to define specific routes
// A router organizes routes into groups, making the app easier to manage.
const router = express.Router();

// Define the port for the server, defaulting to 3000 if not specified in the environment variables
const PORT = process.env.PORT || 3000;

// Middleware to parse URL-encoded form data
// This allows Express to handle data from HTML forms (e.g., registration and login forms).
app.use(express.urlencoded({ extended: true }));

// Middleware to parse JSON request bodies
// This allows Express to handle data sent in JSON format (e.g., API requests).
app.use(express.json());

// Set EJS as the view engine for rendering dynamic HTML templates
// EJS allows embedding JavaScript into HTML for dynamic content.
app.set("view engine", "ejs");

// Set the views directory for EJS templates
// By default, Express looks for a "views" directory in the project root.
// This configuration explicitly sets the path to the "views" folder.
// We could choose a different directory if we wanted (e.g., /templates/)
app.set("views", path.join(__dirname, "views"));

// Connect to MongoDB using the mongoose package
// Mongoose manages the connection to the MongoDB database and provides methods for interacting with it.
mongoose.connect("mongodb://127.0.0.1:27017/Users");

// Define a schema for the Users collection
// A schema defines the structure and rules for documents in a MongoDB collection.
const userSchema = new mongoose.Schema({
    name: { type: String, required: true }, // User's name, required
    password: { type: String, required: true }, // User's password, required
    jobTitle: String, // User's job title, optional
});

// Create a Mongoose model based on the schema
// This will create/interact with a collection "users" in the Users database
// Convention is lowercase and pluralized version of the string we pass in
const User = mongoose.model("User", userSchema);

// Attach the router to the root/api path
// All routes defined on the router will be prefixed with "/api".
app.use("/api", router);

// Start the server and listen on the defined port
// This initializes the server and logs a message indicating where it's running.
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// Define the secret key for JWT from the environment variable
// The secret is used to sign and verify JSON Web Tokens.
const secret = process.env.SECRET;

// Helper function to encode data into a JWT
// Takes a payload (e.g., user data) and generates a token.
function encodeToken(payload) {
    return jwt.encode(payload, secret);
}

// Helper function to decode a JWT
// Takes a token and decodes it back into its original payload.
function decodeToken(token) {
    return jwt.decode(token, secret);
}

// Routes

// Root route: Render the home page
// Displays the main interface for registration, authentication, and status checking.
// Since this uses router.get() instead of app.get()
// the URL will be /api/ instead of /
router.get("/", (req, res) => {
    res.render("index"); // Render the "index" EJS template
});

// Register route: Handles user registration
// Creates a new user in the database if the username doesn't already exist.
router.post("/register", async (req, res) => {

    // Package our form data for processing
    let data =
    {
        name: req.body.username,
        password: req.body.password,
        jobTitle: req.body.jobTitle
    };

    // SANITIZE! For step 3, we want to sanitize our post response instead of just inserting it
    //data = sanitize(data);

    /*
        we'll use the debugger to "inject" the following code into our query
    
        { $gt: "" }
        { $ne: null }
        */

    // try-catch because we get an error after trying to pass invalid data to query after sanitizing.
    try {
        // Check if the username already exists
        const existingUser = await User.findOne({ name: data.name });

        if (existingUser) {
            return res.render("failure", { message: "Username already exists!" });
        }
    } catch (error) {
        return res.render("failure", { message: "Unknown Error!" });
    }

    // Hash the password using bcrypt
    // bcrypt.hash() takes two arguments:
    // - password: the plain text password to hash.
    // - saltRounds: the cost factor, which determines how many hashing iterations to perform (higher = more secure but slower).
    const hashedPassword = await bcrypt.hash(data.password, 10); // 10 is a reasonable value for saltRounds to balance security and performance.
    // Create and save a new user

    //DATA VALIDATION
    /*
    // for this example, assume we're not using a schema that would also
    // validate...
        REMINDER: these is our rules
        var rules = {
            name: "required|min3",
            password: "required|min:5",
            jobTitle: "string",   
        };
     */

    // Validating
    let validation = new Validator(data, rules /*, optionally we could pass in custom error messages*/);

    console.log("Validation Passes: " + validation.passes() + " Validation Fails: " + validation.fails());

    //Make a decision, e.g., redirect to error page if there's a validation error
    if (validation.fails()) {
        let message = `
            name: ${validation.errors.first("name")}, 
            password: ${validation.errors.first("password")}, 
            jobTitle: ${validation.errors.first("jobTitle")}
        `;

        // Redirect to an error page and pass our error messages
        // Ideally we would provide error feedback in the same
        // Page that we accepted the data. In this case, I'm just
        // using the same failure page from before for demonstration.
        return res.render("failure", { message: `Validation error: ${message}` });
    }

    const newUser = new User({ name: data.name, password: hashedPassword, jobTitle: data.jobTitle });
    await newUser.save();

    // Render success page
    res.render("success", { message: "Registration successful! You can now log in.", token: null });
});

// Auth route: Handles user authentication
// Validates user credentials and returns a JWT if successful.
router.post("/auth", async (req, res) => {
    const { username, password } = req.body;

    // Find the user in the database
    const user = await User.findOne({ name: username });
    if (!user) {
        return res.render("failure", { message: "Invalid username or password" });
    }

    // Compare the hashed password in the database with the provided password
    // bcrypt.compare() takes two arguments:
    // - password: the plain text password provided by the user.
    // - user.password: the hashed password stored in the database.
    // It returns a boolean indicating whether the passwords match.
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.render("failure", { message: "Invalid username or password" });
    }

    const token = encodeToken({ name: user.name });
    res.render("success", { message: "Authentication successful", token });
});

// Status route: Validates a token and retrieves user details
router.get("/status", async (req, res) => {
    const token = req.query.token;

    try {
        const payload = decodeToken(token);
        const user = await User.findOne({ name: payload.name });

        if (!user) {
            return res.render("failure", { message: "User not found or invalid token." });
        }

        res.render("status", {
            message: "Token validated successfully",
            name: user.name,
            jobTitle: user.jobTitle,
            token,
        });
    } catch (error) {
        res.render("failure", { message: "Invalid or expired token." });
    }
});

// Modify route: Updates user details and regenerates a new token
router.post("/modify", async (req, res) => {
    const { token, newName, newJobTitle } = req.body;

    try {
        const payload = decodeToken(token);
        const user = await User.findOne({ name: payload.name });

        if (!user) {
            return res.render("failure", { message: "User not found." });
        }

        // Update user details
        if (newName) user.name = newName;
        if (newJobTitle) user.jobTitle = newJobTitle;
        await user.save();

        // Generate new token
        const newToken = encodeToken({ name: user.name });
        res.redirect(`/api/status?token=${newToken}`);
    } catch (error) {
        res.render("failure", { message: "Invalid or expired token." });
    }
});

// Delete route: Deletes the user from the database
router.post("/delete", async (req, res) => {
    const { token, confirm } = req.body;

    if (!confirm) {
        return res.render("failure", { message: "You must confirm user deletion." });
    }

    try {
        const payload = decodeToken(token);
        const user = await User.findOneAndDelete({ name: payload.name });

        if (!user) {
            return res.render("failure", { message: "User not found or invalid token." });
        }

        res.render("success", { message: "User deleted successfully.", token: null });
    } catch (error) {
        res.render("failure", { message: "Invalid or expired token." });
    }
});
