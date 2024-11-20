Node.js User Authentication Examples
====================================

This repository provides two examples of implementing user authentication in Node.js:

1.  **JWT with bcryptjs** (`hashed-server.js`): Demonstrates secure password hashing using `bcryptjs` and token-based authentication with `jwt-simple`.
2.  **JWT only** (`jwt-server.js`): A simpler implementation focusing solely on token-based authentication without password hashing.

Features
--------

*   **User Registration**: Create new users with optional secure password hashing.
*   **User Authentication**: Validate user credentials and generate JSON Web Tokens (JWTs).
*   **Token Validation**: Check the validity of tokens to retrieve user details.
*   **Password Security**: (bcryptjs example) Hashes passwords to protect user credentials.

Prerequisites
-------------

Before running the examples, ensure you have the following installed:

*   [Node.js](https://nodejs.org/) (v14 or higher recommended)
*   [MongoDB](https://www.mongodb.com/) (local or cloud instance)

Installation
------------

1.  Clone the repository:    
    ```
    git clone https://github.com/your-username/nodejs-user-authentication-examples.git cd nodejs-user-authentication-examples
    ```
    
2.  Install dependencies:  
    
    `npm install`
    
3.  Create a `.env` file in the root directory and add your secret key:
    
    `SECRET=your-secret-key`
    
    (use a long randomized string for the secret key, e.g., replace `your-secret-key` with something like `qs3fda95h6z0JUN9wgTy1j2Cl54gB6yzG`)

4.  Start your MongoDB server if running locally and update the MongoDB connection string:

*   In both `jwt-server.js` and `hashed-server.js`, locate the MongoDB connection string:

    `mongoose.connect("mongodb://127.0.0.1:27017/Users");`
    
*   Replace it with your MongoDB connection string if you are using a remote database or a custom local configuration.

Running the Examples
--------------------

1.  **JWT with bcryptjs**:
    
    *   Start the `hashed-server.js`:

        `node hashed-server.js`
        
2.  **JWT only**:
    
    *   Start the `jwt-server.js`:
        
        `node jwt-server.js`
        
3.  Access the APIs at `http://localhost:3000/api` using your browser.
    

API Endpoints
-------------

*   `POST /api/register` - Register a new user.
*   `POST /api/auth` - Authenticate a user and receive a JWT.
*   `GET /api/status?token=TOKEN` - Validate a token and retrieve user details.
*   `POST /api/modify` - Modify user details (requires a token).
*   `POST /api/delete` - Delete a user account (requires a token).
