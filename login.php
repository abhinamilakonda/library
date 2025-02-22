<?php
session_start();

// Database connection
$servername = "localhost";  // Change if your DB is hosted elsewhere
$username = "root";         // Default XAMPP username
$password = "";             // Default XAMPP password (empty)
$database = "information";           // Change to your actual database name

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!empty($_POST['username']) && !empty($_POST['password'])) {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        // Prepare and execute query safely
        $stmt = $conn->prepare("SELECT email, name, password FROM users1 WHERE name = ?");
        if (!$stmt) {
            die("Prepare failed: " . $conn->error);
        }
        
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $user = $result->fetch_assoc();

            // Verify password
            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                echo "<script>alert('Login successful!'); window.location.href='index.html';</script>";
                exit();
            } else {
                echo "<script>alert('Invalid username or password.'); window.location.href='login.php';</script>";
            }
        } else {
            echo "<script>alert('Invalid username or password.'); window.location.href='login.php';</script>";
        }

        $stmt->close();
    } else {
        echo "<script>alert('Please fill in all fields.'); window.location.href='login.php';</script>";
    }
}

$conn->close();
?>
