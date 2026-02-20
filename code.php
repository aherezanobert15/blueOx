<?php
// ================================================
// SINGLE-FILE VERSION - University Innovations Uganda
// Save as index.php and access via browser
// ================================================

// --------------------- DATABASE CONFIG ---------------------
$DB_HOST = 'localhost';
$DB_USER = 'root';
$DB_PASS = '';
$DB_NAME = 'university_innovations';

$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// --------------------- SESSION & HELPERS ---------------------
session_start();

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isLoggedIn() && $_SESSION['role'] === 'admin';
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function h($string) {
    return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
}

function generateCSRF() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRF($token) {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token ?? '');
}

function uploadFile($file, $subfolder = '') {
    if (!isset($file['name']) || $file['error'] !== 0) return false;
    $target_dir = __DIR__ . "/uploads/" . ($subfolder ? $subfolder . '/' : '');
    if (!is_dir($target_dir)) mkdir($target_dir, 0777, true);
    $target_file = $target_dir . basename($file["name"]);
    if (move_uploaded_file($file["tmp_name"], $target_file)) {
        return "uploads/" . ($subfolder ? $subfolder . '/' : '') . basename($file["name"]);
    }
    return false;
}

// --------------------- ROUTING / PAGE HANDLER ---------------------
$page = $_GET['p'] ?? 'home';

$pages = [
    'home'      => 'Home',
    'about'     => 'About',
    'explore'   => 'Explore Innovations',
    'signup'    => 'Signup',
    'login'     => 'Login',
    'upload'    => 'Upload Innovation',
    'admin'     => 'Admin Dashboard',
    'contact'   => 'Contact',
    'privacy'   => 'Privacy & Terms',
];

if (!array_key_exists($page, $pages)) $page = 'home';

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRF($_POST['csrf'] ?? '')) {
        $error = "Invalid CSRF token";
    } else {
        switch ($page) {
            case 'signup':
                $profile_img = uploadFile($_FILES['profile_image'] ?? []);
                $stmt = $conn->prepare("INSERT INTO users (full_name, university, course, year_of_study, email, password_hash, profile_image, role) 
                                        VALUES (?, ?, ?, ?, ?, ?, ?, 'student')");
                $pw_hash = hashPassword($_POST['password']);
                $stmt->bind_param("sssssss", 
                    $_POST['full_name'], $_POST['university'], $_POST['course'], 
                    $_POST['year_of_study'], $_POST['email'], $pw_hash, $profile_img
                );
                if ($stmt->execute()) {
                    $_SESSION['success'] = "Account created! Please log in.";
                    header("Location: ?p=login");
                    exit;
                } else {
                    $error = "Signup failed: " . $conn->error;
                }
                break;

            case 'login':
                $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
                $stmt->bind_param("s", $_POST['email']);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($user = $result->fetch_assoc()) {
                    if (verifyPassword($_POST['password'], $user['password_hash'])) {
                        $_SESSION['user_id'] = $user['user_id'];
                        $_SESSION['role']   = $user['role'];
                        header("Location: ?p=home");
                        exit;
                    } else {
                        $error = "Invalid password";
                    }
                } else {
                    $error = "User not found";
                }
                break;

            case 'upload':
                if (!isLoggedIn()) {
                    header("Location: ?p=login");
                    exit;
                }
                $images = [];
                if (!empty($_FILES['images']['name'][0])) {
                    foreach ($_FILES['images']['tmp_name'] as $i => $tmp) {
                        $f = ['name' => $_FILES['images']['name'][$i], 'tmp_name' => $tmp, 'error' => $_FILES['images']['error'][$i]];
                        if ($path = uploadFile($f, 'innovations')) $images[] = $path;
                    }
                }
                $video = uploadFile($_FILES['video'] ?? [], 'innovations') ?: '';
                $images_str = implode(',', $images);

                $stmt = $conn->prepare("INSERT INTO innovations (user_id, title, sector, stage, description, funding_needed, images, video_link, approval_status) 
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')");
                $funding = floatval($_POST['funding_needed'] ?? 0);
                $stmt->bind_param("issssds", 
                    $_SESSION['user_id'], $_POST['title'], $_POST['sector'], $_POST['stage'], 
                    $_POST['description'], $funding, $images_str, $video
                );
                if ($stmt->execute()) {
                    $_SESSION['success'] = "Innovation submitted and awaiting approval.";
                } else {
                    $error = "Upload failed: " . $conn->error;
                }
                break;

            case 'admin':
                if (!isAdmin()) break;
                if (isset($_POST['approve'])) {
                    $stmt = $conn->prepare("UPDATE innovations SET approval_status = 'approved' WHERE innovation_id = ?");
                    $stmt->bind_param("i", $_POST['id']);
                    $stmt->execute();
                }
                if (isset($_POST['reject'])) {
                    $stmt = $conn->prepare("UPDATE innovations SET approval_status = 'rejected' WHERE innovation_id = ?");
                    $stmt->bind_param("i", $_POST['id']);
                    $stmt->execute();
                }
                break;
        }
    }
}

// Logout
if ($page === 'logout') {
    session_destroy();
    header("Location: ?p=home");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>University Innovations – Uganda</title>
    <style>
        :root {
            --primary: #007A33;
            --accent:  #FCD116;
            --dark:    #000;
            --red:     #E30613;
            --light:   #f8f9fa;
            --gray:    #6c757d;
        }
        body {
            font-family: Arial, Helvetica, sans-serif;
            margin: 0;
            background: var(--light);
            color: #333;
            line-height: 1.6;
        }
        header {
            background: var(--primary);
            color: white;
            padding: 1rem;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }
        nav .logo { font-size: 1.5rem; font-weight: bold; }
        nav ul {
            list-style: none;
            display: flex;
            gap: 1.5rem;
            margin: 0;
            padding: 0;
        }
        nav a { color: white; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
        .hero {
            background: linear-gradient(rgba(0,0,0,0.4), rgba(0,0,0,0.6)), url('https://images.unsplash.com/photo-1522202176988-66273c2b033f?ixlib=rb-4.0.3&auto=format&fit=crop&w=1350&q=80');
            background-size: cover;
            color: white;
            text-align: center;
            padding: 8rem 2rem;
        }
        .hero h1 { margin: 0; font-size: 3rem; }
        .section { margin: 3rem 0; }
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .partners { display: flex; flex-wrap: wrap; gap: 1.5rem; justify-content: center; }
        .partner img { width: 100px; height: 100px; object-fit: contain; }
        form { display: grid; gap: 1rem; max-width: 600px; margin: 2rem auto; }
        input, select, textarea, button {
            padding: 0.8rem;
            border: 1px solid #ccc;
            border-radius: 6px;
            font-size: 1rem;
        }
        button {
            background: var(--primary);
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover { background: #005c26; }
        .innovation-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        .innovation-card img {
            width: 100%;
            height: 180px;
            object-fit: cover;
            border-radius: 6px;
        }
        footer {
            background: var(--dark);
            color: white;
            text-align: center;
            padding: 2rem;
            margin-top: 3rem;
        }
        .message { padding: 1rem; border-radius: 6px; margin: 1rem 0; }
        .success { background: #d4edda; color: #155724; }
        .error   { background: #f8d7da; color: #721c24; }
        @media (max-width: 768px) {
            nav ul { flex-direction: column; gap: 1rem; }
            .hero h1 { font-size: 2.2rem; }
        }
    </style>
</head>
<body>

<header>
    <nav>
        <div class="logo">University Innovations – Uganda</div>
        <ul>
            <li><a href="?p=home">Home</a></li>
            <li><a href="?p=about">About</a></li>
            <li><a href="?p=explore">Explore</a></li>
            <?php if (isLoggedIn()): ?>
                <li><a href="?p=upload">Upload</a></li>
                <?php if (isAdmin()): ?>
                    <li><a href="?p=admin">Admin</a></li>
                <?php endif; ?>
                <li><a href="?p=logout">Logout</a></li>
            <?php else: ?>
                <li><a href="?p=signup">Signup</a></li>
                <li><a href="?p=login">Login</a></li>
            <?php endif; ?>
            <li><a href="?p=contact">Contact</a></li>
            <li><a href="?p=privacy">Privacy</a></li>
        </ul>
    </nav>
</header>

<div class="container">

<?php if (isset($_SESSION['success'])): ?>
    <div class="message success"><?= h($_SESSION['success']) ?></div>
    <?php unset($_SESSION['success']); ?>
<?php endif; ?>

<?php if (isset($error)): ?>
    <div class="message error"><?= h($error) ?></div>
<?php endif; ?>

<?php
// ────────────────────────────────────────────────
// PAGE CONTENT
// ────────────────────────────────────────────────

switch ($page):

    case 'home': ?>
        <section class="hero">
            <h1>Turning University Innovations into Global Impact</h1>
            <p>Showcasing student creativity solving real problems in Uganda and beyond</p>
            <div style="margin: 2rem 0;">
                <a href="?p=upload" style="background:var(--accent);color:var(--dark);padding:1rem 2rem;border-radius:50px;text-decoration:none;font-weight:bold;margin:0 1rem;">Upload Your Innovation</a>
                <a href="?p=explore" style="background:white;color:var(--primary);padding:1rem 2rem;border-radius:50px;text-decoration:none;font-weight:bold;">Explore Innovations</a>
            </div>
        </section>

        <section class="section">
            <h2>Our Partner Universities</h2>
            <div class="partners">
                <?php
                $res = $conn->query("SELECT name, logo FROM universities");
                while ($u = $res->fetch_assoc()) {
                    echo "<div class='partner'><img src='" . h($u['logo']) . "' alt='" . h($u['name']) . "'><p>" . h($u['name']) . "</p></div>";
                }
                ?>
            </div>
        </section>

        <section class="section">
            <h2>Featured Innovations</h2>
            <div class="innovation-grid">
                <?php
                $res = $conn->query("SELECT i.*, u.full_name FROM innovations i JOIN users u ON i.user_id = u.user_id WHERE approval_status = 'approved' LIMIT 6");
                while ($row = $res->fetch_assoc()) {
                    $img = explode(',', $row['images'])[0] ?? 'https://via.placeholder.com/320x180?text=No+Image';
                    echo "<div class='card innovation-card'>";
                    echo "<img src='" . h($img) . "' alt='" . h($row['title']) . "'>";
                    echo "<h3>" . h($row['title']) . "</h3>";
                    echo "<p>" . substr(h($row['description']), 0, 120) . "...</p>";
                    echo "<small>By " . h($row['full_name']) . " • " . h($row['stage']) . "</small>";
                    echo "</div>";
                }
                ?>
            </div>
        </section>
        <?php break;


    case 'about': ?>
        <section class="section">
            <h1>About University Innovations</h1>
            <div class="card">
                <h2>Our Mission</h2>
                <p>To promote, showcase, and connect student-led innovations from Ugandan universities with global partners, sponsors, and investors.</p>
            </div>
            <div class="card">
                <h2>The Problem</h2>
                <p>Many brilliant student innovations remain hidden in university labs due to lack of visibility and funding.</p>
            </div>
            <div class="card">
                <h2>Our Solution</h2>
                <p>A free, open platform where students can upload innovations, and stakeholders can discover and support them.</p>
            </div>
        </section>
        <?php break;


    case 'explore': ?>
        <section class="section">
            <h1>Explore Innovations</h1>
            <div class="innovation-grid">
                <?php
                $res = $conn->query("SELECT i.*, u.full_name, u.university FROM innovations i JOIN users u ON i.user_id = u.user_id WHERE approval_status = 'approved' ORDER BY created_at DESC");
                while ($row = $res->fetch_assoc()) {
                    $img = explode(',', $row['images'])[0] ?? 'https://via.placeholder.com/320x180?text=Innovation';
                    echo "<div class='card innovation-card'>";
                    echo "<img src='" . h($img) . "' alt='" . h($row['title']) . "'>";
                    echo "<h3>" . h($row['title']) . "</h3>";
                    echo "<p>" . nl2br(h(substr($row['description'], 0, 180))) . "...</p>";
                    echo "<p><strong>Sector:</strong> " . h($row['sector']) . "<br>";
                    echo "<strong>Stage:</strong> " . h($row['stage']) . "<br>";
                    echo "<strong>Funding needed:</strong> $" . number_format($row['funding_needed'] ?? 0) . "</p>";
                    echo "<small>By " . h($row['full_name']) . " • " . h($row['university']) . "</small>";
                    echo "</div>";
                }
                if ($res->num_rows === 0) echo "<p>No approved innovations yet.</p>";
                ?>
            </div>
        </section>
        <?php break;


    case 'signup': ?>
        <section class="section">
            <h1>Student Signup</h1>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= generateCSRF() ?>">
                <input type="text"     name="full_name"     placeholder="Full Name" required>
                <select name="university" required>
                    <option value="">Select University</option>
                    <?php
                    $res = $conn->query("SELECT name FROM universities ORDER BY name");
                    while ($u = $res->fetch_assoc()) echo "<option>" . h($u['name']) . "</option>";
                    ?>
                </select>
                <input type="text"     name="course"        placeholder="Course / Program" required>
                <input type="text"     name="year_of_study" placeholder="Year of Study (e.g. 3)" required>
                <input type="email"    name="email"         placeholder="University Email" required>
                <input type="password" name="password"      placeholder="Password" required minlength="6">
                <input type="file"     name="profile_image" accept="image/*">
                <label><input type="checkbox" required> I accept the <a href="?p=privacy">Terms & Privacy Policy</a></label>
                <button type="submit">Create Account</button>
            </form>
            <p style="text-align:center;">Already have an account? <a href="?p=login">Login here</a></p>
        </section>
        <?php break;


    case 'login': ?>
        <section class="section">
            <h1>Login</h1>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= generateCSRF() ?>">
                <input type="email"    name="email"    placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p style="text-align:center;">Don't have an account? <a href="?p=signup">Sign up</a></p>
        </section>
        <?php break;


    case 'upload':
        if (!isLoggedIn()) { header("Location: ?p=login"); exit; } ?>
        <section class="section">
            <h1>Upload Your Innovation</h1>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= generateCSRF() ?>">
                <input type="text"     name="title"           placeholder="Project / Innovation Title" required>
                <select name="sector" required>
                    <option value="">Select Sector</option>
                    <option>Health</option>
                    <option>Agriculture</option>
                    <option>Security</option>
                    <option>ICT</option>
                    <option>Environment</option>
                    <option>Energy</option>
                    <option>Education</option>
                    <option>Manufacturing</option>
                </select>
                <select name="stage" required>
                    <option value="">Development Stage</option>
                    <option>Idea</option>
                    <option>Prototype</option>
                    <option>Beta</option>
                    <option>Market-ready</option>
                </select>
                <textarea name="description" rows="6" placeholder="Describe your innovation, problem solved, and solution..." required></textarea>
                <input type="number"   name="funding_needed" placeholder="Funding needed (USD, optional)" min="0">
                <input type="file"     name="images[]" multiple accept="image/*">
                <input type="file"     name="video" accept="video/*">
                <small>Allowed: images (jpg,png), video (mp4,max 50MB recommended)</small>
                <button type="submit">Submit Innovation</button>
            </form>
        </section>
        <?php break;


    case 'admin':
        if (!isAdmin()) { echo "<h1>Access Denied</h1>"; break; } ?>
        <section class="section">
            <h1>Admin Dashboard</h1>
            <h2>Pending Innovations</h2>
            <?php
            $res = $conn->query("SELECT i.*, u.full_name FROM innovations i JOIN users u ON i.user_id = u.user_id WHERE approval_status = 'pending'");
            if ($res->num_rows === 0) echo "<p>No pending innovations.</p>";
            while ($row = $res->fetch_assoc()) {
                $img = explode(',', $row['images'])[0] ?? 'https://via.placeholder.com/320x180';
                echo "<div class='card' style='margin-bottom:1.5rem;'>";
                echo "<img src='" . h($img) . "' style='max-width:300px;'>";
                echo "<h3>" . h($row['title']) . "</h3>";
                echo "<p>" . nl2br(h(substr($row['description'],0,300))) . "...</p>";
                echo "<p>By: " . h($row['full_name']) . "</p>";
                echo "<form method='post' style='display:inline;'>";
                echo "<input type='hidden' name='id' value='" . $row['innovation_id'] . "'>";
                echo "<button name='approve'>Approve</button>";
                echo "<button name='reject' style='background:#dc3545;'>Reject</button>";
                echo "</form>";
                echo "</div>";
            }
            ?>
        </section>
        <?php break;


    case 'contact': ?>
        <section class="section">
            <h1>Contact Us</h1>
            <div class="card">
                <p><strong>Email:</strong> info@uni-innovations.ug</p>
                <p><strong>Phone:</strong> +256 700 123 456</p>
                <p><strong>Location:</strong> Kampala, Uganda</p>
            </div>
            <form>
                <input type="text" placeholder="Your Name" required>
                <input type="email" placeholder="Email" required>
                <textarea rows="5" placeholder="Your Message" required></textarea>
                <button type="submit">Send Message</button>
            </form>
        </section>
        <?php break;


    case 'privacy': ?>
        <section class="section">
            <h1>Privacy Policy & Terms of Use</h1>
            <div class="card">
                <h2>Privacy</h2>
                <p>We collect minimal personal data (name, email, university) to facilitate connections. Your innovations remain your property. We do not sell data.</p>
            </div>
            <div class="card">
                <h2>Terms</h2>
                <p>Users must upload appropriate content only. We reserve the right to remove any inappropriate or harmful submissions. By using the platform you agree to these terms.</p>
            </div>
        </section>
        <?php break;

endswitch;
?>

</div>

<footer>
    <p>© <?= date("Y") ?> University Innovations – Uganda<br>
    A platform for student innovators | Made with ❤️ in Kampala</p>
</footer>

</body>
</html>

<?php $conn->close(); ?>