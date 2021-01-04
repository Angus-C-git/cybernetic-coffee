---
title: "Building A REST API"
categories: ["Development"]
tags: ["REST API", "Backend", "Node.js", "express"]
date: "2020-12-28"
type: "post"
weight: 400
keywords: "blog REST API "
---

## The Power Of REST APIs

REST APIs are a way to conveniently abstract away application logic and reduce the load on front-end
processing. This is achieved by engineering the API to return data in such a way that we can simply
render it straight out onto the page without sorting or intensive manipulation. In this way we can
achieve faster load times for web pages, and at the same time reduce the amount of JavaScript running 
in users browsers.

REST APIs have many other benefits too, two feature of REST APIs that I frequently exploit is their
ability to remove the need for secret management on the front-end, and their ability to add dynamic 
behaviour to static webapps (like this one). 

You may have seen on the activity page of this site that my recent GitHub activity is rendered as a simple timeline. 
This fetching from the GitHub REST API is done in your browser via a small JS function. This works fine for the Git 
API because large portions of it are exposed unauthenticated meaning there is no need to worry about keys leaking from 
the front-end. 

The same is not true for the Twitter feed, also present on the activity feed page. Even tho I only wish
to pull publicly available data from Twitter an API key is still required. Here a tactic I exploit is 
API chaining, my API which feeds the Twitter activity page acts as a wrapper for the Twitter REST API.
Keeping my twitter access keys secret and exposing only data which is required for site functionality. 

From here it should be apparent that the functionality that a REST API can provide is diverse and relatively
boundless. Let's explore how we can build one for your projects. 

## Getting Started

For this article we will be exploring the creation of a REST API using:

 + Node.js
 + Express.js
 + MongoDB

three of the components which make up part of the exceptionally popular MEAN stack. However, this is but
one approach to building a REST API. Alternatives include combinations of the following:

 + Flask
 + Django
 + Postgres SQL
 + MySQL

However, there are many other stacks too. 

### Dependencies 

There are also a number of libraries present too, which I will explain briefly:

+ Mongoose
   + Wrapper for Mongo DB (our database) which provides us with neat functions for many common tasks like searching
   for specific records
+ CORS
   + Cross-Origin resource sharing is a security oriented feature which allows us to define where requests should come
   from, and which we should respond to/handle. For example often only our front-end website should be able to send
   requests to the API.
+ Bcryptjs
   + Allows us to generate bcrypt hashes for JWT (JSON Web Token) management, our authentication system.
+ Jsonwebtoken
   + Used to generate authentication tokens for the API.
+ dotenv
   + Used for secrets management.
+ @hapi/joi
   + Schema description language and data validator for JavaScript.

### Clone the template

To speed up the process and reduce the boilerplate involved in setting up express, node and the other required
dependencies I have created a template called [RESTPLATE](https://github.com/Angus-C-git/RESTPLATE). To get started
clone the repo:

`git clone https://github.com/Angus-C-git/RESTPLATE.git && cd RESTPLATE`

then install the dependencies with,

`npm install`.

## Using The Template

The template has the following structure, common to many APIS:

```
RESTPLATE/
    /models
        * Post
        * User
    /routes
        * auth
        * posts
        * validateJWT
    * app.js
    * validation.js
    * package.json
    * .env
```

the template is populated with a number of example files including:

 + `models/Post.js`
 + `models/User.js`
 + `routes/posts.js`
 + `routes/auth.js`
 + `routes/validateJWT`
 + `validation.js`

and several core files:

+ `app.js`
+ `package.json`

### Models

Files under the `models` directory define database objects (which can be thought of as traditional database tables). 
This definition includes the fields found in the database schema, and their properties which typically includes: 

 + The type of the data; String, Number, Array ...
 + If the field is required
 + The minimum and maximum length of the data in the field

The Post model from the template:

```javascript
const mongoose = require('mongoose');

// DB Post schema
const postSchema = new mongoose.Schema({
    author: {
        type: String,
        required: true,
        min: 6,
        max: 25
    },
    message: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Post', postSchema);
```

### Routes

Files under the `routes` directory correlate to endpoints that can be 'hit' (interacted with) by clients. Interactions
for a REST API are the HTTP methods:

 + `GET`
    + Fetch a resource
 + `POST`
    + Send a resource
 + `PUT`
    + Update a resource
 + `DELETE`
    + Remove a resource

the included routes in the template only demonstrate usage of `GET` and `POST` but the other methods are fairly 
self-explanatory. 

Lets take a look at the `posts` route. 

```javascript
const router = require('express').Router();
const verify = require('./validateJWT');  // Authenticated route
const Post = require('../models/Post');   // Post model


/**
 * Fetch all shared posts ...
 * */
router.get('/', verify, async (req, res) => {
    try {
        const posts = await Post.find();
        res.status(200).json(posts);
    } catch (err) {
        res.status(503).json({error: err});
    }
});


/**
 * Share a post ...
 * */
router.post('/', verify, async (req, res) => {
    const post = new Post({
        author: req.body.author,
        postContents: req.body.postContents
    });

    try {
        const savedPost = await post.save();
        res.status(200).json(savedPost);
    } catch (err) {
        res.status(503).json({error: err});
    }
});

module.exports = router;
```

As discussed above a route will define HTTP methods that the endpoint can handle. This is typically inferred from the 
name of the endpoint. We would expect on your average website which has a page called posts that we would be able
to **share** a post and **view** other posts. These terms map to the HTTP methods `GET` and `POST` on the backend. In 
many cases one would also expect to be able to **remove** (`DELETE`) a post, however we will not discuss this here.

#### GET


The `router.get ...` line in the code means that the route (in this case `/api/posts,
discussed later)` accepts `GET` requests from a client. The route handler then queries the mongo database, with 
`Post.find()`, to retrieve all the posts stored there. 

The API then returns the found posts as a JSON object with, 

```javascript
res.status(200).json(posts);
```

where status code 200 indicates a request ok.

#### POST

The `router.post...` line in the code means that `POST` requests made to this endpoint will be handled by this function.
When the `POST` route is hit the function looks to create a new `Post` database object. Normally we would validate the 
`POST` request body sent to the route to avoid processing a malformed request, I.E one where a required field was left out.
This process can be observed in the provided `auth` route,

```javascript
const {error} = registerSchema.validate(req.body);

if (error) {
    let err = error.details[0].message;
    return res.status(400).send(err);
}
```
where an error will be thrown if the provided schema does not match the format of the defined register schema.

### Authenticated Routes

In a lot of cases you will not want to allow anyone on the internet access to your routes, for example you can't view posts
on instagram without creating an account. To provide this protection we implement authenticated routes, authenticated
routes act as a way to ensure that only authenticated (registered) users can interact with a given endpoint.

In the template this manifests as the `verify` parameter in the route header,

```javascript
router.get('/', verify, async (req, res) => { ...}
```

which will drop requests which do not include a valid authentication header in the request.

The verify function, exported from the `validateJWT` route, looks like this:

```javascript
const jwt = require('jsonwebtoken');

/**
 * Validate Auth Tokens
 */
module.exports = function (req, res, next) {
    const token = req.header('auth-token');
    if (!token) return res.status(401).send('Access Denied');

    try {
        // JWT middleware
        req.user = jwt.verify(token, process.env.TOKEN_SECRET);
        next();
    } catch (err) {
        res.status(403).send('Invalid Token');
    }
}
```

The first thing to note is that we require the `jsonwebtoken` library in order to generate authentication tokens. Next
we perform a precursor check to ensure that an authentication token is present before we continue creating an early
exit and reducing processing time of clearly invalid requests. 

Next we enter the crux of the function:

```javascript
req.user = jwt.verify(token, process.env.TOKEN_SECRET);
```
where we pass the token provided in the request header to the `verify()` function which checks that the provided token
is signed correctly in accordance with the signing secret, stored as an environment variable (in our .env file). If the
token is valid the `next()` call continues the execution from whence `verify` was called. Otherwise, a 403 is returned, 
and an error message sent.

### The API Core: `app.js`

To bind all of this functionality together we require a runner of sorts which maps inbound requests to the server to
the appropriate routes and implements server configurations. This is where the `app.js` file comes into play.

```javascript
/**
 * <-------------------------> IMPORTS <------------------------->
 * */

const express = require('express');     // Express JS
const dotenv = require('dotenv');       // Environment variables
const mongoose = require('mongoose');   // Mongo DB Wrapper
const cors = require('cors');           // Cross Origin Security Headers

const app = express();
dotenv.config();

// DB Connection init
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () => {
        console.log("Connected to db...");
});

// Middlewares
app.use(express.json());
app.use(cors());

/**
 * <---------------------------> ROUTES <--------------------------->
 * */

// Basic JWT auth routes
const authRoute = require('./routes/auth');

// Example posts route
const posts = require('./routes/posts');

/**
 * <---------------------> ROUTE MIDDLEWARES <---------------------->
 * */

app.use('/api/user', authRoute);
app.use('/api/posts', posts);


// API Base Endpoint
app.get("/", (Req, res) => {
    res.send("Running ..");
});

/**
 * <-----------------------> DEVOPS RUNNER <------------------------>
 * */

let port = process.env.PORT;
// dev mode switch
port = (!port || port === "") ? 8000 : port;

// API Listener init
app.listen(port);
```

First we see a number of our dependencies being imported with require and some configuration settings being bound with

```javascript
const app = express();
dotenv.config();
```

and 

```javascript
app.use(express.json());
app.use(cors());
```

of note here is that `cors` is currently set to accept all origins, this should be adjusted to something like

```javascript
const corsOptions = {
    origin: 'http://my-site.com',
    optionsSuccessStatus: 200
}
```

and then used on routes like this

```javascript
app.get('/posts', cors(corsOptions), function (req, res, next) {
  res.json({msg: 'Only requests from http://my-site.com will reach here'});
})
```

in order to prevent access to the API from origins other than the frontend webapp. 

The next important function here is,

```javascript
// DB Connection init
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () => {
        console.log("Connected to db...");
});
```

which establishes a connection to the Mongo database by passing the database connection token stored in the `.env` file.
This will allow the API to interact with the database in later functions.

The following two blocks establish how requests to specific endpoints should be mapped internally. Firstly we establish
the functions/files that should handle calls to a particular endpoint and store them in associated variables.

```javascript
// route file to handel authentication
const authRoute = require('./routes/auth');
// route file to handel post logic
const posts = require('./routes/posts');    
```

Then we point specific external endpoints to these routes to be handled. 

```javascript
app.use('/api/user', authRoute);
app.use('/api/posts', posts);
```

Finally, we use a neat ternary operation to determine how the server should listen based on if the server is being run 
locally in development mode or in production.

```javascript
// presence of enviroment variable PORT indicates prod mode
let port = process.env.PORT; 
// listen on port 8000 in dev mode
port = (!port || port === "") ? 8000 : port; 
// API Listener init
app.listen(port);
```

## Wrangling the API to Your Needs

Adapting the API to suite your needs will mostly involve writing additional routes and creating additional models. 
Doing so is a relatively straightforward process of wrangling existing route and model code to your needs and adding 
support for additional HTTP methods. For routes that alter data the database will also need to be updated in order
for changes to persist. Mongoose should make this a relatively simple process as well since it is well documented, and
most IDE autocomplete libraries should provide enough details to implement common methods.

For more information the following resources should be enough to implement most functionality:

+ [Mongoose Documentation](https://mongoosejs.com/docs/index.html)
+ [HTTP Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)
+ [CORS](https://www.npmjs.com/package/cors)
+ [Express Basic Routing](http://expressjs.com/en/starter/basic-routing.html)
+ [JWT Disassembly](https://jwt.io/)

## Hosting The REST API

### Database

For database hosting we will be using MongoDB's own solution: [Atlas](https://www.mongodb.com/cloud/atlas). To begin with
create an account, and a new cluster.

After spinning up a new cluster you will need to set up a user to authenticate to the DBMs and connect via your Node.js
server. These credentials will then be stored in your `.env` file and used to establish a connection to the database
after your node server starts up.

To start the setup process:

`Your-Cluster => Connect => Create A User`

### API Server

There are a number of different options for hosting code for free these days some of my go to's are:

+ Firebase
+ Heroku
+ Surge

but for this tutorial we will stick with Heroku for the hosting of the Node.js server. To begin with authenticate with
heroku,

`heroku login`

then create a project on heroku with,

`heroku create your-api-name`.

Then stage and commit your changes with git.

```shell
git add .
git commit -m "commit_message"
```

Finally, push your changes to heroku.

```shell
git push heroku master`
```

*Note*: If you get an error you may need to add your projects git remote as a remote origin.

## Testing the API With Postman

The final step is to test your API routes to ensure they behave as expected in all situations. [Postman](https://www.postman.com/) allows us to
achieve this coverage by providing a clean UI, and a bunch of useful functionality to test our routes. Start by downloading
the application and setting up a new project.

### Testing A Route

To demonstrate we will use postman to test the `/api/user/register` route from the template. I'll be using the local
development server to demonstrate this, but the only difference is your url will replace `http://localhost:8000` with
`https://your-sites-domain`. 

First setup a new request like the one bellow:

{{< image ref="images/blog/register-test-post.png" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[Postman Route Setup]</b>
    </p>
{{< /md_html >}}

Then add a JSON body with the required fields to register a user under the 'Body' tab.

```json
{
  "usrName": "devTest1",
  "email": "devtest1@email.com",
  "password": "stronkPasswd"
}
```

{{< image ref="images/blog/register-test-res.png" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[Testing Valid Register]</b>
    </p>
{{< /md_html >}}

We see that if we send the post request to the running backend server we are returned a JWT for the newly registered 
user. Here we should also test that the API responds appropriately to invalid and malformed requests such as a 
register request which is missing one of the required fields.

{{< image ref="images/blog/register-test-missing.png" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[Testing Missing Fields]</b>
    </p>
{{< /md_html >}}

### Testing Authenticated Routes

To test a route which requires authentication we simply need to pass a valid JWT as a header with the required header
name, in our case 'auth-token'. 


{{< image ref="images/blog/test-auth-route.png" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[Testing Protected Routes]</b>
    </p>
{{< /md_html >}}


~> If you have any comments or questions feel free to leave them on this [thread](https://twitter.com/ghostinthefiber/status/1344281710372954115).
