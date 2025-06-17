CREATE DATABASE maintananceDB;

USE maintananceDB;

-- all tables start with "maintenance_"
CREATE TABLE maintenance_users(
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(200) NOT NULL UNIQUE,
    username VARCHAR(200) NOT NULL,
    password_hash VARCHAR(200),
    user_type ENUM("Admin", "Visitor", "Technician") NOT NULL DEFAULT 'Visitor',
    salt VARCHAR(200),
    api_key VARCHAR(200)
);

-- locations (factory / department )
CREATE TABLE maintenance_locations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(200) NOT NULL UNIQUE
);

-- machines
CREATE TABLE maintenance_machines (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(200) NOT NULL,
    
    location_id INT,
    installed_at DATE DEFAULT CURRENT_DATE,

    FOREIGN KEY (location_id) REFERENCES maintenance_locations(id) ON DELETE SET NULL
);

--logs
CREATE TABLE maintenance_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    priority ENUM("Low", "Medium", "High", "Critical") DEFAULT 'Low',
    status ENUM("Pending", "Active", "Resolved") DEFAULT 'Pending',

    machine_id INT,
    location_id INT,
    assigned_to INT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (machine_id) REFERENCES maintenance_machines(id) ON DELETE SET NULL,
    FOREIGN KEY (location_id) REFERENCES maintenance_locations(id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_to) REFERENCES maintenance_users(id) ON DELETE SET NULL
);

-- machine_history
CREATE TABLE maintenance_machine_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    machine_id INT,
    location_id INT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at DATE,
    resolved_at DATE,

    FOREIGN KEY (machine_id) REFERENCES maintenance_machines(id) ON DELETE SET NULL,
    FOREIGN KEY (location_id) REFERENCES maintenance_locations(id) ON DELETE SET NULL
);

