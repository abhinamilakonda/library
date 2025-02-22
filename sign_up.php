<?php
// Start the session to store any error or success messages
session_start();

// Database connection variables
$servername = "localhost";  // Change to your database server address if needed
$username = "root";         // Your database username
$password = "";             // Your database password
$dbname = "information";  // Replace with your actual database name

// Create a connection to the MySQL database
$conn = new mysqli($servername, $username, $password, $dbname);

// Check if the connection was successful
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize variables to store form data and error messages
$name = $email = $password = $confirmPassword = "";
$nameErr = $emailErr = $passwordErr = $confirmPasswordErr = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate Full Name
    if (empty($_POST["name"])) {
        $nameErr = "Full Name is required.";
    } else {
        $name = clean_input($_POST["name"]);
    }

    // Validate Email
    if (empty($_POST["email"])) {
        $emailErr = "Email is required.";
    } else {
        $email = clean_input($_POST["email"]);
        // Check if the email format is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $emailErr = "Invalid email format.";
        }
    }

    // Validate Password
    if (empty($_POST["password"])) {
        $passwordErr = "Password is required.";
    } else {
        $password = clean_input($_POST["password"]);
        // Ensure password is strong enough (optional)
        if (strlen($password) < 6) {
            $passwordErr = "Password must be at least 6 characters long.";
        }
    }

    // Validate Confirm Password
    if (empty($_POST["confirm-password"])) {
        $confirmPasswordErr = "Confirm Password is required.";
    } else {
        $confirmPassword = clean_input($_POST["confirm-password"]);
        // Check if the passwords match
        if ($password !== $confirmPassword) {
            $confirmPasswordErr = "Passwords do not match.";
        }
    }

    // If there are no errors, process the data (e.g., save to the database)
    if (empty($nameErr) && empty($emailErr) && empty($passwordErr) && empty($confirmPasswordErr)) {
        // Hash the password before saving it to the database
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Prepare SQL statement to insert user data into the database
        $stmt = $conn->prepare("INSERT INTO users1 (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $hashedPassword);

        // Execute the prepared statement
        if ($stmt->execute()) {
            // Set a success message in the session (optional)
            $_SESSION['success'] = "Signup successful! You can now sign in.";
            
            // Optionally, you can directly display the success message on the same page:
            echo "<script>window.location.href='index.html';</script>";
        } else {
            // Handle any errors here
            echo "<p style='color: red;'>Error: " . $stmt->error . "</p>";
        }


        // Close the prepared statement
        $stmt->close();
    }
}

// Close the database connection
$conn->close();

// Function to sanitize user input
function clean_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}
?>