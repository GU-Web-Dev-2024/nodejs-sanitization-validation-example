Nodejs Data Sanitization and Validation (Demo)
====================================

The following is a modified version of [this project](https://github.com/GU-Web-Dev-2024/nodejs-user-authentication-examples)

Overview
--------

This project is a demonstration of secure user management using Node.js. It highlights essential techniques for **data sanitization** and **validation** to mitigate vulnerabilities and ensure data integrity. The application includes CRUD operations and JWT-based authentication.

* * *

Features
--------

*   **Data Sanitization:** Protects against MongoDB query injection using [`mongo-sanitize`](https://www.npmjs.com/package/mongo-sanitize).
*   **Data Validation:** Enforces input validation rules with [`validatorjs`](https://www.npmjs.com/package/validatorjs).
*   **Secure Password Storage:** Hashes passwords using `bcryptjs`.
*   **JWT Authentication:** Secures session management.

* * *

Key Concepts
------------

### **Data Sanitization**

This application sanitizes input to protect against injection attacks. For example, consider the following input:

*   **Injected Data:**   
    
    `{ "name": { "$ne": null } }`
    
*   **Sanitized Data:**
        
    `{ "name": "[object Object]" }`
    

Sanitization removes any special query selectors, ensuring only valid data reaches the database.

*   **Setup:**
    
    `npm install mongo-sanitize`
    
*   **Usage:**
            
    ```
    const sanitize = require("mongo-sanitize");
    const sanitizedData = sanitize(req.body);
    ```    

* * *

### **Data Validation**

Validation ensures data meets [specified rules](https://www.npmjs.com/package/validatorjs#available-rules). For example:

*   **Ruleset for ValidatorJS:**
    
    ```
    const rules = {
         name: "required|min:3",
         password: "required|min:5",
         email: "required|email",
         age: "min:18"
    };
    ```
    

Validation guarantees the following:

*   `name`: Must be at least 3 characters and cannot be empty.
    
*   `password`: Must be at least 5 characters long.
    
*   `email`: Must follow a valid email format.
    
*   `age`: Must be at least 18.
    
*   **Setup:**
       
    `npm install validatorjs`
    
*   **Usage:**
        
    ```
    const Validator = require("validatorjs");
    const validation = new Validator(data, rules);  
    
    if (validation.fails()) {
             console.log(validation.errors.all()); 
    }
    ```
    

* * *

Environment Variables
---------------------

Sensitive data is stored in a `.env` file:

*   `PORT`: Application port
*   `SECRET`: JWT secret key

* * *

Security Practices
------------------

1.  **Input Sanitization:** Mitigates injection attacks.
2.  **Validation Rules:** Ensures data integrity and reliability.
3.  **Password Hashing:** Protects user credentials.

* * *

Run Instructions
----------------

1.  Install dependencies:
    
    `npm install`
    
2.  Configure `.env` with required variables.
3.  Start the server:
        
    `node server.js`
    
4.  Access the application at `http://localhost:<PORT>/api`.

* * *

References
----------

*   [MongoDB Injection Prevention](https://medium.com/@SW_Integrity/mongodb-preventing-common-vulnerabilities-in-the-mean-stack-ac27c97198ec)
*   [Mongo Sanitize](https://www.npmjs.com/package/mongo-sanitize)
*   [Query Selector Injection Attacks](https://thecodebarbarian.wordpress.com/2014/09/04/defending-against-query-selector-injection-attacks/)
*   [Securing MongoDB](https://severalnines.com/database-blog/securing-mongodb-external-injection-attacks)
*   [ValidatorJS Documentation](https://www.npmjs.com/package/validatorjs)
*   [LogRocket ValidatorJS Guide](https://blog.logrocket.com/how-to-handle-data-validation-in-node-using-validatorjs/)

