from fastapi import FastAPI, HTTPException

app = FastAPI(title="AURA Demo API")


# -------------------------
# Users
# -------------------------

users = [
    {
        "id": 1,
        "name": "Alice",
        "username": "alice",
        "password": "alice123",
        "role": "user"
    },
    {
        "id": 2,
        "name": "Bob",
        "username": "bob",
        "password": "bob123",
        "role": "user"
    },
    {
        "id": 3,
        "name": "Admin",
        "username": "admin",
        "password": "admin123",
        "role": "admin"
    }
]


# -------------------------
# Home
# -------------------------

@app.get("/")
def home():
    return {"message": "AURA Demo API is running"}


# -------------------------
# Get Users
# -------------------------

@app.get("/users")
def get_users():
    return [
        {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"]
        }
        for user in users
    ]


# -------------------------
# Login
# -------------------------

@app.post("/login")
def login(username: str, password: str):

    for user in users:

        if user["username"] == username and user["password"] == password:

            return {
                "message": "Login successful",
                "user_id": user["id"],
                "name": user["name"],
                "role": user["role"]
            }

    raise HTTPException(
        status_code=401,
        detail="Invalid username or password"
    )
orders = [
    {
        "id": 101,
        "user_id": 1,
        "product": "Laptop",
        "amount": 55000
    },
    {
        "id": 102,
        "user_id": 2,
        "product": "Headphones",
        "amount": 3000
    }
]
@app.get("/orders/{order_id}")
def get_order(order_id: int):

    for order in orders:
        if order["id"] == order_id:
            return order

    raise HTTPException(
        status_code=404,
        detail="Order not found"
    )
@app.get("/admin/reports")
def admin_reports(username: str):
    for user in users:
        if user["username"] == username:
            return {
                "message": "Admin reports",
                "user": user["name"],
                "role": user["role"],
                "total_orders": len(orders),
                "status": "confidential"
            }

    raise HTTPException(
        status_code=404,
        detail="User not found"
    )
@app.get("/secure/orders/{order_id}")
def secure_order(order_id: int, username: str):
    for user in users:
        if user["username"] == username:

            for order in orders:
                if order["id"] == order_id:

                    # Allow only the owner
                    if order["user_id"] == user["id"]:
                        return order

                    raise HTTPException(
                        status_code=403,
                        detail="You are not allowed to access this order"
                    )

            raise HTTPException(
                status_code=404,
                detail="Order not found"
            )

    raise HTTPException(
        status_code=404,
        detail="User not found"
    )
@app.get("/profiles/{user_id}")
def get_profile(user_id: int):
    for user in users:
        if user["id"] == user_id:
            return {
                "user_id": user["id"],
                "name": user["name"],
                "role": user["role"]
            }

    raise HTTPException(
        status_code=404,
        detail="User not found"
    )