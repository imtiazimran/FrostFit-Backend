# L2B2-Frontend-Path-Assignment-6-Server-Starter-Pack

## Installation:

1. Clone the repository.
2. Install dependencies using `npm install`.
3. Rename `.env.example` to `.env`.
4. Run the server using `npm run dev`.

## Configuration:

- Environment Variables:
  - `PORT`: Port number the server listens on. Default: 3000
  - `MONGODB_URI`: URI for MongoDB database.
  - `JWT_SECRET`: Secret key for JWT token generation.
  - `EXPIRES_IN`: Token expiration time.

## For Live Link: [Click Here](https://frostfitserver.vercel.app)

## Usage:

### API Endpoints:

#### Authentication:

- **POST `/api/auth/register`**

  - Registers a new user.
  - Request Body:
    ```json
    {
      "name": "John",
      "email": "example@email.com",
      "password": "password"
    }
    ```
  - Response:
    ```json
    {
      "success": true,
      "message": "User registered successfully",
      "token": "<JWT Token>"
    }
    ```

- **POST `/api/auth/login`**
  - Authenticates user and returns a JWT token.
  - Request Body:
    ```json
    {
      "email": "example@email.com",
      "password": "password"
    }
    ```
  - Response:
    ```json
    {
      "success": true,
      "message": "Login successful",
      "token": "<JWT Token>",
      "user": { "name": "John", "email": "example@email.com" }
    }
    ```

#### Users:

- **GET `/api/v1/users`**

  - Retrieves all users.
  - Requires authentication.
  - Response:
    ```json
    {
        "success": true,
        "message": "Users retrieved successfully",
        "users": [...]
    }
    ```

- **GET `/api/v1/user`**
  - Retrieves the authenticated user's details.
  - Requires authentication.
  - Response:
    ```json
    {
      "success": true,
      "message": "User retrieved successfully",
      "user": { "name": "John", "email": "example@email.com" }
    }
    ```

#### Clothes:

- **POST `/api/v1/cloth`**

  - Adds a new cloth item.
  - Requires authentication.
  - Request Body:
    ```json
    {
      "category": "Jackets",
      "title": "Winter Jacket",
      "sizes": ["M", "L", "XL"],
      "description": "Warm jacket suitable for cold weather.",
      "img": "https://example.com/jacket.jpg",
      "amount": 100
    }
    ```
  - Response:
    ```json
    {
        "success": true,
        "message": "Cloth added successfully",
        "result": { ...insertedClothData }
    }
    ```

- **GET `/api/v1/clothes`**

  - Retrieves all cloth items added by the authenticated user.
  - Requires authentication.
  - Response:
    ```json
    {
        "success": true,
        "message": "Clothes retrieved successfully",
        "clothes": [...]
    }
    ```

- **GET `/api/v1/cloth/:id`**

  - Retrieves a specific cloth item by ID.
  - Requires authentication.
  - Response:
    ```json
    {
        "success": true,
        "message": "Cloth retrieved successfully",
        "cloth": { ...clothData }
    }
    ```

- **PATCH `/api/v1/cloth/:id`**

  - Updates a specific cloth item by ID.
  - Requires authentication.
  - Request Body:
    ```json
    {
      "category": "Jackets",
      "title": "Updated Jacket Title",
      "sizes": ["L", "XL"],
      "description": "Updated description.",
      "img": "https://example.com/updated.jpg"
    }
    ```
  - Response:
    ```json
    {
        "success": true,
        "message": "Cloth updated successfully",
        "result": { ...updateResult }
    }
    ```

- **DELETE `/api/v1/cloth/:id`**
  - Deletes a specific cloth item by ID.
  - Requires authentication.
  - Response:
    ```json
    {
        "success": true,
        "message": "Cloth deleted successfully",
        "result": { ...deleteResult }
    }
    ```

#### Donations:

- **POST `/api/v1/donate`**
  - Processes a donation for a specific cloth item.
  - Requires authentication.
  - Request Body:
    ```json
    {
      "id": "<clothItemId>",
      "amount": 50
    }
    ```
  - Response:
    ```json
    {
        "success": true,
        "message": "Donation successful",
        "result": { ...donationUpdateResult }
    }
    ```

#### Statistics:

- **GET `/api/v1/statistics`**
  - Retrieves statistics including total users, total clothes, and total donations.
  - Requires authentication.
  - Response:
    ```json
    {
      "success": true,
      "message": "Statistics retrieved successfully",
      "totalUsers": 10,
      "totalClothes": 50,
      "totalDonations": 500
    }
    ```

## Dependencies:

- `bcrypt`: Library for hashing passwords.
- `cors`: Express middleware for enabling CORS.
- `dotenv`: Loads environment variables from .env file.
- `express`: Web framework for Node.js.
- `jsonwebtoken`: Library for generating and verifying JWT tokens.
- `mongodb`: MongoDB driver for Node.js.
- `nodemon`: Utility for automatically restarting the server during development.
