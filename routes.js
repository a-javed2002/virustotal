var express = require("express");
const { body, validationResult } = require("express-validator");
var mysql = require("mysql");
var jwt = require("jsonwebtoken");
var LocalStorage = require("node-localstorage").LocalStorage;
const localStorage = new LocalStorage("./scratch");
/* GET home page. */

function checkLoginUser(req, res, next) {
  var userToken = localStorage.getItem("userToken");
  try {
    var decoded = jwt.verify(userToken, "loginToken");
  } catch (err) {
    res.redirect("/");
  }
  next();
}

const router = express.Router();

const db = mysql.createConnection({
  host: "localhost",
  port: 3306,
  user: "root",
  password: "",
  database: "shahmir",
});

db.connect((err) => {
  if (err) {
    throw err;
  } else {
    console.log("MySql is connected");
  }
});

function extractTokenData(req, res, next) {
  // Get the token from the Authorization header
  // const token = req.headers.authorization;
  const token = localStorage.getItem("userToken");

  if (token) {
    try {
      // Verify the token
      const decodedToken = jwt.verify(token, "loginToken");

      // Attach token data to the request for later use
      req.tokenData = {
        username: decodedToken.username,
        useremail: decodedToken.useremail,
        role_id: decodedToken.role_id,
        role_name: decodedToken.role_name,
        userId: decodedToken.user_id,
      };

      // Continue with the next middleware or route handler
      next();
    } catch (error) {
      // Handle token verification error
      console.error("Token verification failed:", error.message);
      // return res.status(401).json({ error: 'Token verification failed' });
      return res.redirect("/");
    }
  } else {
    // Token is not present in the request
    // return res.status(401).json({ error: 'Token not provided' });
    return res.redirect("/");
  }
}

// Validation middleware for the user insertion form
const validateUser = [
  body("name").notEmpty().withMessage("Name is required"),
  body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
  body("pwd")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
];

// Route for handling the user insertion form with validation
router.post("/insertUser", extractTokenData, validateUser, async (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Validation errors occurred, render the form with errors
      return res.status(400).render("home", { errors: errors.array() });
    }

    const { name, email, pwd } = req.body;

    // SQL query to insert user into the 'users' table
    const query = `
      INSERT INTO users (name, email, password, role_id_fk, joined_at, updated_at)
      VALUES (?, ?, ?, ?, NOW(), NOW())
    `;

    // Execute the query
    db.query(query, [name, email, pwd, role_id], (error, result) => {
      if (error) {
        console.error("Error inserting user:", error);
        return res.redirect("/error");
      }

      console.log("User inserted successfully:", result);

      // Redirect to a success page or send a response
      res.redirect("/success");
    });
  } catch (error) {
    console.error("Error inserting user:", error);

    // Redirect to an error page or send an error response
    res.redirect("/error");
  }
});

router.get("/add-new-malware", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name, userId } = req.tokenData;

  res.render("add-new-malware", {
    errors: "",
    title: "QAS Dashboard",
    loginUser: username,
    role: role_name,
    role_id: role_id,
  });
});

// POST route for form submission
router.post("/add-new-malware", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name, userId } = req.tokenData;

  // Check for validation errors
  const errors = validationResult(req);
  console.log(req.body);
  console.log("-----------------------");


  // Extract data from the form submission
  const {
    fileHash,
    fileSize,
    fileType,
    malwareCategory,
    dateTime,
    descriptionOfIncident,
    threatLevel,
    ipAddress,
    domainName,
    url,
    registryKey,
    filePath,
    behaviorDescription,
    systemCallsOrAPIFunctions,
    registryModifications,
    YARARules,
    patchInformation,
    actorNameOrAlias,
    motivation,
    TTPs,
    knownAffiliations,
    vulnerabilityType,
    affectedSoftwareOrSystemComponent,
    CVE_ID,
    patchStatus,
  } = req.body;

  var status = 0;

  if (role_id == 1) {
    status = 1;
  }

  // Insert data into the MySQL database
  const insertQuery1 =
    "INSERT INTO malwaresample (fileHash,fileSize,fileType,malwareCategory,status,user_id_fk) VALUES (?,?, ?, ?, ?,?)";

  db.query(
    insertQuery1,
    [fileHash, fileSize, fileType, malwareCategory, status, userId],
    (err, result) => {
      if (err) {
        // Handle the error (you might want to send an error response to the client)
        console.error("Error inserting data malwaresample:", err);
        return res.status(500).send("Internal Server Error");
      }

      // Data inserted successfully
      console.log("Data inserted successfully malwaresample:", result);
      console.log(result.insertId);
      const MalwareSample_id_fk = result.insertId;

      // Redirect or render a success page

      const insertQuery2 =
        "INSERT INTO incidentreport (dateTime,descriptionOfIncident,threatLevel,MalwareSample_id_fk) VALUES (?,?, ?, ?)";

      db.query(
        insertQuery2,
        [dateTime, descriptionOfIncident, threatLevel, MalwareSample_id_fk],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data incidentreport:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log("Data inserted successfully incidentreport:", result);

          // Redirect or render a success page
        }
      );

      // Insert data into the MySQL database
      const insertQuery3 =
        "INSERT INTO indicatorsofcompromise (ipAddress,domainName,url,registryKey,filePath,MalwareSample_id_fk) VALUES (?,?, ?, ?, ?,?)";

      db.query(
        insertQuery3,
        [ipAddress, domainName, url, registryKey, filePath, MalwareSample_id_fk],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data indicatorsofcompromise:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log(
            "Data inserted successfully indicatorsofcompromise:",
            result
          );

          // Redirect or render a success page
        }
      );

      // Insert data into the MySQL database
      const insertQuery4 =
        "INSERT INTO maliciousbehavior (behaviorDescription,systemCallsOrAPIFunctions,registryModifications,MalwareSample_id_fk) VALUES (?,?, ?, ?)";

      db.query(
        insertQuery4,
        [
          behaviorDescription,
          systemCallsOrAPIFunctions,
          registryModifications,
          MalwareSample_id_fk,
        ],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data maliciousbehavior:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log("Data inserted successfully maliciousbehavior:", result);

          // Redirect or render a success page
        }
      );

      // Insert data into the MySQL database
      const insertQuery5 =
        "INSERT INTO mitigationstrategy (YARARules,patchInformation,MalwareSample_id_fk) VALUES (?,?, ?)";

      db.query(
        insertQuery5,
        [YARARules, patchInformation, MalwareSample_id_fk],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data mitigationstrategy:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log("Data inserted successfully mitigationstrategy:", result);
        }
      );

      // Insert data into the MySQL database
      const insertQuery6 =
        "INSERT INTO threatactor (actorNameOrAlias,motivation,TTPs,knownAffiliations,MalwareSample_id_fk) VALUES (?,?, ?, ?,?)";

      db.query(
        insertQuery6,
        [
          actorNameOrAlias,
          motivation,
          TTPs,
          knownAffiliations,
          MalwareSample_id_fk,
        ],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data threatactor:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log("Data inserted successfully threatactor:", result);

          // Redirect or render a success page
        }
      );

      // Insert data into the MySQL database
      const insertQuery7 =
        "INSERT INTO vulnerabilityexploited (vulnerabilityType,affectedSoftwareOrSystemComponent,CVE_ID,patchStatus,MalwareSample_id_fk) VALUES (?,?, ?, ?,?)";

      db.query(
        insertQuery7,
        [
          vulnerabilityType,
          affectedSoftwareOrSystemComponent,
          CVE_ID,
          patchStatus,
          MalwareSample_id_fk,
        ],
        (err, result) => {
          if (err) {
            // Handle the error (you might want to send an error response to the client)
            console.error("Error inserting data vulnerabilityexploited:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Data inserted successfully
          console.log(
            "Data inserted successfully vulnerabilityexploited:",
            result
          );

          // Redirect or render a success page
        }
      );

      // Redirect or render a success page
      res.redirect("/view-all-malware");
    }
  );
});

router.get("/view-all-malware", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name,userId } = req.tokenData;
  // Retrieve data from the MySQL database
  // var selectQuery ="SELECT malware.id as id,malware.name as name,malware.type as type,malware.asset_effected as asset_effected,malware.description as description,malware.status as status,malware.created_at as created_at,malware.user_id_fk.user_name as user1,malware.incident_owner_id_fk .user_name as user2 user.status as user_status, user.user_id as user_id, user.user_name as user_name FROM malware INNER JOIN `user` on user_id_fk=user_id";
  var selectQuery;

  if(role_id==1){
    selectQuery = `
  SELECT
    malwaresample.*,
    user.*,
    incidentreport.*,
    indicatorsofcompromise.*,
    maliciousbehavior.*,
    threatactor.*,
    vulnerabilityexploited.*
  FROM malwaresample
  INNER JOIN user ON malwaresample.user_id_fk = user.user_id
  INNER JOIN incidentreport ON malwaresample.MalwareSample_id = incidentreport.MalwareSample_id_fk
  INNER JOIN indicatorsofcompromise ON malwaresample.MalwareSample_id = indicatorsofcompromise.MalwareSample_id_fk
  INNER JOIN maliciousbehavior ON malwaresample.MalwareSample_id = maliciousbehavior.MalwareSample_id_fk
  INNER JOIN mitigationstrategy ON malwaresample.MalwareSample_id = mitigationstrategy.MalwareSample_id_fk
  INNER JOIN threatactor ON malwaresample.MalwareSample_id = threatactor.MalwareSample_id_fk
  INNER JOIN vulnerabilityexploited ON malwaresample.MalwareSample_id = vulnerabilityexploited.MalwareSample_id_fk`;

  db.query(selectQuery, (err, malware) => {
    if (err) {
      // Handle the error (you might want to send an error response to the client)
      console.error("Error retrieving data:", err);
      return res.status(500).send("Internal Server Error");
    }

    console.log(malware);

    // Render the view with the retrieved malware data
    res.render("view-all-malware", {
      title: "View All malware",
      loginUser: username,
      role: role_name,
      role_id: role_id, // Assuming you have a way to get the logged-in user
      malware: malware, // Pass the malware data to the view
    });
  });
  }
  else{
    selectQuery = `
  SELECT
    malwaresample.*,
    user.*,
    incidentreport.*,
    indicatorsofcompromise.*,
    maliciousbehavior.*,
    threatactor.*,
    vulnerabilityexploited.*
  FROM malwaresample
  INNER JOIN user ON malwaresample.user_id_fk = user.user_id
  INNER JOIN incidentreport ON malwaresample.MalwareSample_id = incidentreport.MalwareSample_id_fk
  INNER JOIN indicatorsofcompromise ON malwaresample.MalwareSample_id = indicatorsofcompromise.MalwareSample_id_fk
  INNER JOIN maliciousbehavior ON malwaresample.MalwareSample_id = maliciousbehavior.MalwareSample_id_fk
  INNER JOIN mitigationstrategy ON malwaresample.MalwareSample_id = mitigationstrategy.MalwareSample_id_fk
  INNER JOIN threatactor ON malwaresample.MalwareSample_id = threatactor.MalwareSample_id_fk
  INNER JOIN vulnerabilityexploited ON malwaresample.MalwareSample_id = vulnerabilityexploited.MalwareSample_id_fk
  WHERE malwaresample.user_id_fk =?`;

  db.query(selectQuery,[userId], (err, malware) => {
    if (err) {
      // Handle the error (you might want to send an error response to the client)
      console.error("Error retrieving data:", err);
      return res.status(500).send("Internal Server Error");
    }

    console.log(malware);

    // Render the view with the retrieved malware data
    res.render("view-all-malware", {
      title: "View All malware",
      loginUser: username,
      role: role_name,
      role_id: role_id, // Assuming you have a way to get the logged-in user
      malware: malware, // Pass the malware data to the view
    });
  });
  }


});

//----------------------------------------------------------------------------------//
router.get("/add-new-users", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name } = req.tokenData;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  res.render("add-new-users", {
    errors: "",
    title: "QAS Dashboard",
    loginUser: username,
    role: role_name,
    role_id: role_id,
  });
});

// Validation middleware using express-validator
const validateUserForm = [
  body("name").notEmpty().withMessage("Name is required"),
  body("email")
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Invalid email format"),
  body("password").notEmpty().withMessage("Password is required"),
  body("role").notEmpty().withMessage("Role is required"),
];

// POST route for form submission (add-new-user)
router.post(
  "/add-new-users",
  extractTokenData,
  validateUserForm,
  function (req, res) {
    const { username, useremail, role_id, role_name } = req.tokenData;
    if (role_id != 1) {
      return res.status(500).send("Only Admin Can Access This");
    }
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // If there are validation errors, render the form with error messages
      return res.render("add-new-users", {
        errors: errors.mapped(),
        title: "Add User",
        loginUser: username,
        role: role_name,
        role_id: role_id,
      });
    }

    // Extract data from the form submission
    const { name, email, password, role } = req.body;

    // Insert data into the MySQL database
    const insertQuery =
      "INSERT INTO `user` (user_name, user_email, user_password, role_id_fk) VALUES (?, ?, ?, ?)";

    db.query(insertQuery, [name, email, password, role], (err, result) => {
      if (err) {
        // Handle the error (you might want to send an error response to the client)
        console.error("Error inserting user data:", err);
        return res.status(500).send("Internal Server Error");
      }

      // Data inserted successfully
      console.log("User data inserted successfully:", result);

      // Redirect or render a success page
      res.redirect("/view-all-users"); // You can replace "/success" with the desired success page
    });
  }
);

// GET route to view all users
router.get("/view-all-users", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name, userId } = req.tokenData;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  console.log("Id is " + userId);
  // Retrieve data from the MySQL database
  const selectQuery =
    "SELECT * FROM `user` INNER JOIN role on role_id_fk=role_id WHERE user_id!=?";

  db.query(selectQuery, [userId], (err, users) => {
    if (err) {
      // Handle the error (you might want to send an error response to the client)
      console.error("Error retrieving users:", err);
      return res.status(500).send("Internal Server Error");
    }

    // Render the view with the retrieved users data
    res.render("view-all-users", {
      title: "View All Users",
      loginUser: username,
      role: role_name,
      role_id: role_id, // Assuming you have a way to get the logged-in user
      users: users, // Pass the users data to the view
    });
  });
});

//---------------------------------------------ADMIN--------------------------------------------------------------//
// Edit Incident Route
router.get("/edit-malware/:id", extractTokenData, async (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  const malwareId = req.params.id;

  const query = `
  SELECT
    malwaresample.*,
    incidentreport.dateTime,
    incidentreport.descriptionOfIncident,
    incidentreport.threatLevel,
    indicatorsofcompromise.ipAddress,
    indicatorsofcompromise.domainName,
    indicatorsofcompromise.url,
    indicatorsofcompromise.registryKey,
    indicatorsofcompromise.filePath,
    maliciousbehavior.behaviorDescription,
    maliciousbehavior.systemCallsOrAPIFunctions,
    maliciousbehavior.registryModifications,
    mitigationstrategy.YARARules,
    mitigationstrategy.patchInformation,
    threatactor.actorNameOrAlias,
    threatactor.motivation,
    threatactor.TTPs,
    threatactor.knownAffiliations,
    vulnerabilityexploited.vulnerabilityType,
    vulnerabilityexploited.affectedSoftwareOrSystemComponent,
    vulnerabilityexploited.CVE_ID,
    vulnerabilityexploited.patchStatus
  FROM malwaresample
  INNER JOIN incidentreport ON malwaresample.MalwareSample_id = incidentreport.MalwareSample_id_fk
  INNER JOIN indicatorsofcompromise ON malwaresample.MalwareSample_id = indicatorsofcompromise.MalwareSample_id_fk
  INNER JOIN maliciousbehavior ON malwaresample.MalwareSample_id = maliciousbehavior.MalwareSample_id_fk
  INNER JOIN mitigationstrategy ON malwaresample.MalwareSample_id = mitigationstrategy.MalwareSample_id_fk
  INNER JOIN threatactor ON malwaresample.MalwareSample_id = threatactor.MalwareSample_id_fk
  INNER JOIN vulnerabilityexploited ON malwaresample.MalwareSample_id = vulnerabilityexploited.MalwareSample_id_fk
  WHERE malwaresample.MalwareSample_id = ?`;

  db.query(query, [malwareId], (err, results) => {
    if (err) {
      console.error("Error fetching malware data:", err);
      return res.status(500).send("Internal Server Error");
    }

    // Assuming results is an array with user data
    const malware = results[0];

    // Render your edit-user.ejs template with the user data
    res.render("edit-malware", {
      malware,
      loginUser: username,
      errors: "",
      role: role_name,
      role_id: role_id,
    });
  });
});

// Delete Malware Route
router.get("/delete-malware/:id", extractTokenData, async (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  if (role_id !== 1) {
    return res.status(500).send("Only Admin Can Access This");
  }

  const malwareId = req.params.id;

  try {
    // Start a transaction to ensure consistency across all delete operations
    await db.beginTransaction();

    // Delete data from the incidentreport table
    await db.query("DELETE FROM incidentreport WHERE MalwareSample_id_fk = ?", [
      malwareId,
    ]);

    // Delete data from the indicatorsofcompromise table
    await db.query(
      "DELETE FROM indicatorsofcompromise WHERE MalwareSample_id_fk = ?",
      [malwareId]
    );

    // Delete data from the maliciousbehavior table
    await db.query(
      "DELETE FROM maliciousbehavior WHERE MalwareSample_id_fk = ?",
      [malwareId]
    );

    // Delete data from the mitigationstrategy table
    await db.query(
      "DELETE FROM mitigationstrategy WHERE MalwareSample_id_fk = ?",
      [malwareId]
    );

    // Delete data from the threatactor table
    await db.query("DELETE FROM threatactor WHERE MalwareSample_id_fk = ?", [
      malwareId,
    ]);

    // Delete data from the vulnerabilityexploited table
    await db.query(
      "DELETE FROM vulnerabilityexploited WHERE MalwareSample_id_fk = ?",
      [malwareId]
    );

    // Finally, delete data from the malwaresample table
    await db.query("DELETE FROM malwaresample WHERE MalwareSample_id = ?", [
      malwareId,
    ]);

    // Commit the transaction
    await db.commit();

    // Redirect to the malware list
    res.redirect("/view-all-malware");
  } catch (error) {
    // Rollback the transaction in case of an error
    await db.rollback();

    console.error("Error deleting malware:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Update Incident Route
router.post("/update-malware/:id", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name, userId } = req.tokenData;
  const malwareId = req.params.id; // Extract the malware ID from the request parameters

  // Check for validation errors
  const errors = validationResult(req);
  console.log(req.body);
  console.log("-----------------------");

  // Extract data from the form submission
  const {
    fileHash,
    fileSize,
    fileType,
    malwareCategory,
    status,
    dateTime,
    descriptionOfIncident,
    threatLevel,
    ipAddress,
    domainName,
    url,
    registryKey,
    filePath,
    behaviorDescription,
    systemCallsOrAPIFunctions,
    registryModifications,
    YARARules,
    patchInformation,
    actorNameOrAlias,
    motivation,
    TTPs,
    knownAffiliations,
    vulnerabilityType,
    affectedSoftwareOrSystemComponent,
    CVE_ID,
    patchStatus,
  } = req.body;

  // Update data in the MySQL database - malwaresample table
  const updateQuery1 = `
      UPDATE malwaresample
      SET
          fileHash = ?, fileSize = ?, fileType = ?, malwareCategory = ?,
          status = ?, user_id_fk = ?
      WHERE MalwareSample_id = ?`;

  db.query(
    updateQuery1,
    [fileHash, fileSize, fileType, malwareCategory, status, userId, malwareId],
    (err, result) => {
      if (err) {
        console.error("Error updating data malwaresample:", err);
        return res.status(500).send("Internal Server Error");
      }

      // Update data in the MySQL database - incidentreport table
      const updateQuery2 = `
          UPDATE incidentreport
          SET
              dateTime = ?, descriptionOfIncident = ?, threatLevel = ?
          WHERE MalwareSample_id_fk = ?`;

      db.query(
        updateQuery2,
        [dateTime, descriptionOfIncident, threatLevel, malwareId],
        (err, result) => {
          if (err) {
            console.error("Error updating data incidentreport:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Update data in the MySQL database - indicatorsofcompromise table
          const updateQuery3 = `
              UPDATE indicatorsofcompromise
              SET
                  ipAddress = ?, domainName = ?, url = ?,
                  registryKey = ?, filePath = ?
              WHERE MalwareSample_id_fk = ?`;

          db.query(
            updateQuery3,
            [ipAddress, domainName, url, registryKey, filePath, malwareId],
            (err, result) => {
              if (err) {
                console.error(
                  "Error updating data indicatorsofcompromise:",
                  err
                );
                return res.status(500).send("Internal Server Error");
              }

              // Update data in the MySQL database - maliciousbehavior table
              const updateQuery4 = `
                  UPDATE maliciousbehavior
                  SET
                      behaviorDescription = ?, systemCallsOrAPIFunctions = ?,
                      registryModifications = ?
                  WHERE MalwareSample_id_fk = ?`;

              db.query(
                updateQuery4,
                [
                  behaviorDescription,
                  systemCallsOrAPIFunctions,
                  registryModifications,
                  malwareId,
                ],
                (err, result) => {
                  if (err) {
                    console.error(
                      "Error updating data maliciousbehavior:",
                      err
                    );
                    return res.status(500).send("Internal Server Error");
                  }

                  // Update data in the MySQL database - mitigationstrategy table
                  const updateQuery5 = `
                      UPDATE mitigationstrategy
                      SET
                          YARARules = ?, patchInformation = ?
                      WHERE MalwareSample_id_fk = ?`;

                  db.query(
                    updateQuery5,
                    [YARARules, patchInformation, malwareId],
                    (err, result) => {
                      if (err) {
                        console.error(
                          "Error updating data mitigationstrategy:",
                          err
                        );
                        return res.status(500).send("Internal Server Error");
                      }

                      // Update data in the MySQL database - threatactor table
                      const updateQuery6 = `
                          UPDATE threatactor
                          SET
                              actorNameOrAlias = ?, motivation = ?,
                              TTPs = ?, knownAffiliations = ?
                          WHERE MalwareSample_id_fk = ?`;

                      db.query(
                        updateQuery6,
                        [
                          actorNameOrAlias,
                          motivation,
                          TTPs,
                          knownAffiliations,
                          malwareId,
                        ],
                        (err, result) => {
                          if (err) {
                            console.error(
                              "Error updating data threatactor:",
                              err
                            );
                            return res
                              .status(500)
                              .send("Internal Server Error");
                          }

                          // Update data in the MySQL database - vulnerabilityexploited table
                          const updateQuery7 = `
                              UPDATE vulnerabilityexploited
                              SET
                                  vulnerabilityType = ?, affectedSoftwareOrSystemComponent = ?,
                                  CVE_ID = ?, patchStatus = ?
                              WHERE MalwareSample_id_fk = ?`;

                          db.query(
                            updateQuery7,
                            [
                              vulnerabilityType,
                              affectedSoftwareOrSystemComponent,
                              CVE_ID,
                              patchStatus,
                              malwareId,
                            ],
                            (err, result) => {
                              if (err) {
                                console.error(
                                  "Error updating data vulnerabilityexploited:",
                                  err
                                );
                                return res
                                  .status(500)
                                  .send("Internal Server Error");
                              }

                              // Redirect or render a success page
                              res.redirect("/view-all-malware");
                            }
                          );
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
});

//--------------------//
// Fetch user data based on user_id
router.get("/edit-user/:id", extractTokenData, (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  const userId = req.params.id;

  // Replace the following with your actual database query to fetch user data
  const query = "SELECT * FROM user WHERE user_id = ?";
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching user data:", err);
      return res.status(500).send("Internal Server Error");
    }

    // Assuming results is an array with user data
    const user = results[0];

    // Render your edit-user.ejs template with the user data
    res.render("edit-user", {
      user,
      loginUser: username,
      errors: "",
      role: role_name,
      role_id: role_id,
    });
  });
});

// Delete User Route
router.get("/delete-user/:id", extractTokenData, async (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  const userId = req.params.id;

  try {
    console.log("i'm here");
    // Delete the user from the database
    await db.query("DELETE FROM user WHERE user_id = ?", [userId]);

    // Redirect to the users list
    res.redirect("/view-all-users");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Update User Route
router.post("/update-user/:id", extractTokenData, async (req, res) => {
  const { username, useremail, role_id, role_name } = req.tokenData;
  const userId = req.params.id;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  // Extract user data from the request body
  const { name, email, password, role, status } = req.body;

  // Validate the data (you can use a validation library or custom logic)

  try {
    // Update the user data in the database
    await db.query(
      "UPDATE user SET user_name=?, user_email=?, user_password=?, role_id_fk=?,user_status=? WHERE user_id=?",
      [name, email, password, role, status, userId]
    );

    // Redirect to the users list or show a success message
    res.redirect("/view-all-users");
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Internal Server Error");
  }
});

//--------------------//
//--------------------//

//-----------------------------------------------------------------------------------------------------------//

module.exports = router;
