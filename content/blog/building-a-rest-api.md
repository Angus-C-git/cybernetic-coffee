---
title: "Building A REST API"
weight: 400
keywords: "blog REST API "
---

-----

## The Power Of REST APIs

REST APIs are a way to conveniently abstract away application logic and reduce the load on front-end
processing. This is achieved by engineering the API to return data in such a way that we can simply
render it straight out onto the page without sorting or intensive manipulation. In this way we can
achieve faster load times for web pages, and at the same time reduce the amount of JavaScript running 
in users browsers.

REST APIs have many other benefits too, two feature of REST APIs that I frequently exploit is their
ability to remove the need for secret management on the front-end, and their ability to add dynamic 
behaviour to static webapps (like this one). You may have seen on the activity page of this site that
my recent GitHub activity is rendered as a simple timeline. This fetching from the GitHub REST API is
done in your browser via a small JS function. This works fine for the Git API because large portions of
it are exposed unauthenticated meaning there is no need to worry about keys leaking from the front-end.
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

### Clone the template

To speed up the process and reduce the boilerplate involved in setting up express, node and the other required
dependencies I have created a template called [RESTPLATE](https://github.com/Angus-C-git/RESTPLATE). To get started
clone the repo:

`git clone https://github.com/Angus-C-git/RESTPLATE.git && cd RESTPLATE`

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

#### Models

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

#### Routes

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

##### GET


The `router.get ...` line in the code means that the route (in this case `/api/posts,
discussed later)` accepts `GET` requests from a client. The route handler then queries the mongo database, with 
`Post.find()`, to retrieve all the posts stored there. 

The API then returns the found posts as a JSON object with, 

```javascript
res.status(200).json(posts);
```

where status code 200 indicates a request ok.

##### POST

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

#### Authenticated Routes

In a lot of cases you will not want to allow anyone on the internet access to your routes, for example you can't view posts
on instagram without creating an account. To provide this protection we implement authenticated routes, authenticated
routes act as a way to ensure that only authenticated (registered) users can interact with a given endpoint.

In the template this manifests as the `verify` parameter in the route header,

```javascript
router.get('/', verify, async (req, res) => { ...}
```


## Wrangling the API to Your Needs

Coming soon ...

## Hosting The REST API

Coming soon ...

### Database

Coming soon ...

### The API

Coming soon ...